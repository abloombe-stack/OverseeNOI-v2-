// =====================================================
// REAL-TIME WEBSOCKET GATEWAY
// =====================================================

// src/realtime/realtime.gateway.ts
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  ConnectedSocket,
  MessageBody,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Injectable, Logger, UseGuards } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { RBACService } from '../auth/rbac.service';
import { EventEmitter2, OnEvent } from '@nestjs/event-emitter';

interface ConnectedUser {
  userId: string;
  socketId: string;
  propertyIds: string[];
  lastActivity: Date;
  userAgent?: string;
}

@WebSocketGateway({
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
  },
  namespace: '/realtime',
})
@Injectable()
export class RealtimeGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(RealtimeGateway.name);
  private connectedUsers = new Map<string, ConnectedUser>();
  private userSockets = new Map<string, Set<string>>(); // userId -> Set of socketIds

  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
    private rbacService: RBACService,
    private eventEmitter: EventEmitter2,
  ) {}

  async handleConnection(client: Socket) {
    try {
      // Authenticate user
      const token = client.handshake.auth?.token || client.handshake.headers?.authorization?.replace('Bearer ', '');
      if (!token) {
        client.disconnect();
        return;
      }

      const payload = this.jwtService.verify(token);
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
        include: {
          roles: {
            include: { property: true },
          },
        },
      });

      if (!user) {
        client.disconnect();
        return;
      }

      // Get user's accessible properties
      const propertyIds = await this.getUserPropertyIds(user.id);

      // Store connection
      const connectedUser: ConnectedUser = {
        userId: user.id,
        socketId: client.id,
        propertyIds,
        lastActivity: new Date(),
        userAgent: client.handshake.headers['user-agent'],
      };

      this.connectedUsers.set(client.id, connectedUser);
      
      if (!this.userSockets.has(user.id)) {
        this.userSockets.set(user.id, new Set());
      }
      this.userSockets.get(user.id)!.add(client.id);

      // Join property rooms
      propertyIds.forEach(propertyId => {
        client.join(`property:${propertyId}`);
      });

      // Join user-specific room
      client.join(`user:${user.id}`);

      this.logger.log(`User ${user.displayName} connected (${client.id})`);

      // Send initial presence update
      this.broadcastPresenceUpdate(user.id, 'online');

      // Send any pending notifications
      await this.sendPendingNotifications(client, user.id);

    } catch (error) {
      this.logger.error('Connection authentication failed:', error);
      client.disconnect();
    }
  }

  handleDisconnect(client: Socket) {
    const connectedUser = this.connectedUsers.get(client.id);
    if (connectedUser) {
      const { userId } = connectedUser;
      
      // Remove from tracking
      this.connectedUsers.delete(client.id);
      this.userSockets.get(userId)?.delete(client.id);
      
      // If no more connections for this user, mark as offline
      if (this.userSockets.get(userId)?.size === 0) {
        this.userSockets.delete(userId);
        this.broadcastPresenceUpdate(userId, 'offline');
      }

      this.logger.log(`User disconnected (${client.id})`);
    }
  }

  @SubscribeMessage('heartbeat')
  handleHeartbeat(@ConnectedSocket() client: Socket) {
    const connectedUser = this.connectedUsers.get(client.id);
    if (connectedUser) {
      connectedUser.lastActivity = new Date();
    }
    client.emit('heartbeat_ack');
  }

  @SubscribeMessage('join_channel')
  async handleJoinChannel(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { channelId: string }
  ) {
    const connectedUser = this.connectedUsers.get(client.id);
    if (!connectedUser) return;

    // Verify user has access to this channel
    const channel = await this.prisma.channel.findUnique({
      where: { id: data.channelId },
    });

    if (channel && connectedUser.propertyIds.includes(channel.propertyId)) {
      client.join(`channel:${data.channelId}`);
      client.emit('channel_joined', { channelId: data.channelId });
    } else {
      client.emit('error', { message: 'Access denied to channel' });
    }
  }

  @SubscribeMessage('leave_channel')
  handleLeaveChannel(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { channelId: string }
  ) {
    client.leave(`channel:${data.channelId}`);
    client.emit('channel_left', { channelId: data.channelId });
  }

  @SubscribeMessage('typing_start')
  handleTypingStart(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { channelId: string }
  ) {
    const connectedUser = this.connectedUsers.get(client.id);
    if (connectedUser) {
      client.to(`channel:${data.channelId}`).emit('user_typing', {
        userId: connectedUser.userId,
        channelId: data.channelId,
      });
    }
  }

  @SubscribeMessage('typing_stop')
  handleTypingStop(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { channelId: string }
  ) {
    const connectedUser = this.connectedUsers.get(client.id);
    if (connectedUser) {
      client.to(`channel:${data.channelId}`).emit('user_stopped_typing', {
        userId: connectedUser.userId,
        channelId: data.channelId,
      });
    }
  }

  // Event handlers for real-time updates
  @OnEvent('task.created')
  handleTaskCreated(payload: any) {
    this.server.to(`channel:${payload.task.channelId}`).emit('task_created', payload.task);
  }

  @OnEvent('task.updated')
  handleTaskUpdated(payload: any) {
    this.server.to(`channel:${payload.task.channelId}`).emit('task_updated', payload.task);
  }

  @OnEvent('task.completed')
  handleTaskCompleted(payload: any) {
    this.server.to(`channel:${payload.task.channelId}`).emit('task_completed', payload.task);
  }

  @OnEvent('message.created')
  handleMessageCreated(payload: any) {
    const rooms = [`channel:${payload.message.channelId}`];
    if (payload.message.taskId) {
      rooms.push(`task:${payload.message.taskId}`);
    }
    
    rooms.forEach(room => {
      this.server.to(room).emit('message_created', payload.message);
    });
  }

  @OnEvent('notification.sent')
  handleNotificationSent(payload: any) {
    this.server.to(`user:${payload.userId}`).emit('notification', payload.notification);
  }

  @OnEvent('rent_roll.anomaly')
  handleRentRollAnomaly(payload: any) {
    this.server.to(`property:${payload.propertyId}`).emit('rent_roll_anomaly', payload);
  }

  @OnEvent('competitor.price_change')
  handleCompetitorPriceChange(payload: any) {
    this.server.to(`property:${payload.propertyId}`).emit('competitor_alert', payload);
  }

  @OnEvent('system.maintenance')
  handleSystemMaintenance(payload: any) {
    this.server.emit('system_maintenance', payload);
  }

  // Utility methods
  async broadcastToProperty(propertyId: string, event: string, data: any) {
    this.server.to(`property:${propertyId}`).emit(event, data);
  }

  async broadcastToUser(userId: string, event: string, data: any) {
    this.server.to(`user:${userId}`).emit(event, data);
  }

  async broadcastToChannel(channelId: string, event: string, data: any) {
    this.server.to(`channel:${channelId}`).emit(event, data);
  }

  getConnectedUsers(): ConnectedUser[] {
    return Array.from(this.connectedUsers.values());
  }

  getUserPresence(userId: string): 'online' | 'away' | 'offline' {
    const userSocketIds = this.userSockets.get(userId);
    if (!userSocketIds || userSocketIds.size === 0) {
      return 'offline';
    }

    // Check if any socket has recent activity
    const now = new Date();
    const activeThreshold = 5 * 60 * 1000; // 5 minutes

    for (const socketId of userSocketIds) {
      const connectedUser = this.connectedUsers.get(socketId);
      if (connectedUser && now.getTime() - connectedUser.lastActivity.getTime() < activeThreshold) {
        return 'online';
      }
    }

    return 'away';
  }

  private async getUserPropertyIds(userId: string): Promise<string[]> {
    const userRoles = await this.prisma.userRole.findMany({
      where: { userId },
    });

    const propertyIds = userRoles
      .filter(role => role.propertyId)
      .map(role => role.propertyId);

    // If user has company-wide access, get all company properties
    const hasCompanyAccess = userRoles.some(role => !role.propertyId);
    if (hasCompanyAccess) {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        include: {
          company: {
            include: {
              portfolios: {
                include: { properties: true },
              },
            },
          },
        },
      });

      return user?.company.portfolios
        .flatMap(portfolio => portfolio.properties)
        .map(property => property.id) || [];
    }

    return propertyIds;
  }

  private broadcastPresenceUpdate(userId: string, status: 'online' | 'offline') {
    this.server.emit('user_presence_updated', { userId, status });
  }

  private async sendPendingNotifications(client: Socket, userId: string) {
    const pendingNotifications = await this.prisma.notification.findMany({
      where: {
        userId,
        read: false,
        createdAt: {
          gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // Last 7 days
        },
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    if (pendingNotifications.length > 0) {
      client.emit('pending_notifications', pendingNotifications);
    }
  }
}

// =====================================================
// MOBILE APP FOUNDATION (REACT NATIVE)
// =====================================================

// mobile/App.tsx
import React, { useEffect, useState } from 'react';
import {
  NavigationContainer,
  DefaultTheme,
  DarkTheme,
} from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createStackNavigator } from '@react-navigation/stack';
import {
  StatusBar,
  useColorScheme,
  Platform,
  Alert,
} from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import AsyncStorage from '@react-native-async-storage/async-storage';
import PushNotification from 'react-native-push-notification';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

// Services
import { AuthService } from './src/services/AuthService';
import { RealtimeService } from './src/services/RealtimeService';
import { NotificationService } from './src/services/NotificationService';

// Screens
import LoginScreen from './src/screens/LoginScreen';
import DashboardScreen from './src/screens/DashboardScreen';
import PropertiesScreen from './src/screens/PropertiesScreen';
import TasksScreen from './src/screens/TasksScreen';
import MessagesScreen from './src/screens/MessagesScreen';
import ProfileScreen from './src/screens/ProfileScreen';
import PropertyDetailScreen from './src/screens/PropertyDetailScreen';
import TaskDetailScreen from './src/screens/TaskDetailScreen';
import ChatScreen from './src/screens/ChatScreen';

// Context
import { AuthProvider, useAuth } from './src/context/AuthContext';
import { RealtimeProvider } from './src/context/RealtimeContext';

const Tab = createBottomTabNavigator();
const Stack = createStackNavigator();

const AuthStack = () => (
  <Stack.Navigator screenOptions={{ headerShown: false }}>
    <Stack.Screen name="Login" component={LoginScreen} />
  </Stack.Navigator>
);

const DashboardStack = () => (
  <Stack.Navigator>
    <Stack.Screen 
      name="Dashboard" 
      component={DashboardScreen}
      options={{ title: 'OverseeNOI' }}
    />
  </Stack.Navigator>
);

const PropertiesStack = () => (
  <Stack.Navigator>
    <Stack.Screen 
      name="Properties" 
      component={PropertiesScreen}
      options={{ title: 'Properties' }}
    />
    <Stack.Screen 
      name="PropertyDetail" 
      component={PropertyDetailScreen}
      options={{ title: 'Property Details' }}
    />
  </Stack.Navigator>
);

const TasksStack = () => (
  <Stack.Navigator>
    <Stack.Screen 
      name="Tasks" 
      component={TasksScreen}
      options={{ title: 'Tasks' }}
    />
    <Stack.Screen 
      name="TaskDetail" 
      component={TaskDetailScreen}
      options={{ title: 'Task Details' }}
    />
  </Stack.Navigator>
);

const MessagesStack = () => (
  <Stack.Navigator>
    <Stack.Screen 
      name="Messages" 
      component={MessagesScreen}
      options={{ title: 'Messages' }}
    />
    <Stack.Screen 
      name="Chat" 
      component={ChatScreen}
      options={{ title: 'Chat' }}
    />
  </Stack.Navigator>
);

const ProfileStack = () => (
  <Stack.Navigator>
    <Stack.Screen 
      name="Profile" 
      component={ProfileScreen}
      options={{ title: 'Profile' }}
    />
  </Stack.Navigator>
);

const TabNavigator = () => (
  <Tab.Navigator
    screenOptions={{
      tabBarActiveTintColor: '#3B82F6',
      tabBarInactiveTintColor: '#6B7280',
      headerShown: false,
    }}
  >
    <Tab.Screen
      name="DashboardTab"
      component={DashboardStack}
      options={{
        tabBarLabel: 'Dashboard',
        tabBarIcon: ({ color, size }) => (
          <Icon name="view-dashboard" color={color} size={size} />
        ),
      }}
    />
    <Tab.Screen
      name="PropertiesTab"
      component={PropertiesStack}
      options={{
        tabBarLabel: 'Properties',
        tabBarIcon: ({ color, size }) => (
          <Icon name="office-building" color={color} size={size} />
        ),
      }}
    />
    <Tab.Screen
      name="TasksTab"
      component={TasksStack}
      options={{
        tabBarLabel: 'Tasks',
        tabBarIcon: ({ color, size }) => (
          <Icon name="checkbox-marked-circle" color={color} size={size} />
        ),
      }}
    />
    <Tab.Screen
      name="MessagesTab"
      component={MessagesStack}
      options={{
        tabBarLabel: 'Messages',
        tabBarIcon: ({ color, size }) => (
          <Icon name="message-text" color={color} size={size} />
        ),
      }}
    />
    <Tab.Screen
      name="ProfileTab"
      component={ProfileStack}
      options={{
        tabBarLabel: 'Profile',
        tabBarIcon: ({ color, size }) => (
          <Icon name="account" color={color} size={size} />
        ),
      }}
    />
  </Tab.Navigator>
);

const AppNavigator = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return null; // Or loading screen
  }

  return user ? <TabNavigator /> : <AuthStack />;
};

const App = () => {
  const isDarkMode = useColorScheme() === 'dark';
  const [notificationToken, setNotificationToken] = useState<string | null>(null);

  useEffect(() => {
    // Configure push notifications
    PushNotification.configure({
      onRegister: (token) => {
        console.log('Push notification token:', token);
        setNotificationToken(token.token);
        NotificationService.registerToken(token.token);
      },
      onNotification: (notification) => {
        console.log('Notification received:', notification);
        NotificationService.handleNotification(notification);
      },
      permissions: {
        alert: true,
        badge: true,
        sound: true,
      },
      popInitialNotification: true,
      requestPermissions: Platform.OS === 'ios',
    });

    // Request notification permissions on Android
    if (Platform.OS === 'android') {
      PushNotification.requestPermissions();
    }
  }, []);

  return (
    <SafeAreaProvider>
      <AuthProvider>
        <RealtimeProvider>
          <NavigationContainer theme={isDarkMode ? DarkTheme : DefaultTheme}>
            <StatusBar
              barStyle={isDarkMode ? 'light-content' : 'dark-content'}
              backgroundColor={isDarkMode ? '#000000' : '#FFFFFF'}
            />
            <AppNavigator />
          </NavigationContainer>
        </RealtimeProvider>
      </AuthProvider>
    </SafeAreaProvider>
  );
};

export default App;

// mobile/src/services/AuthService.ts
import AsyncStorage from '@react-native-async-storage/async-storage';
import { ApiService } from './ApiService';

export interface User {
  id: string;
  email: string;
  displayName: string;
  avatar?: string;
  company: {
    id: string;
    name: string;
  };
  roles: Array<{
    role: string;
    propertyId?: string;
  }>;
}

export class AuthService {
  private static TOKEN_KEY = '@oversee_auth_token';
  private static USER_KEY = '@oversee_user_data';

  static async login(email: string, password: string): Promise<{ user: User; token: string }> {
    try {
      const response = await ApiService.post('/auth/login', {
        email,
        password,
      });

      const { user, token } = response.data;

      // Store token and user data
      await AsyncStorage.setItem(this.TOKEN_KEY, token);
      await AsyncStorage.setItem(this.USER_KEY, JSON.stringify(user));

      // Set API authorization header
      ApiService.setAuthToken(token);

      return { user, token };
    } catch (error) {
      throw new Error('Login failed. Please check your credentials.');
    }
  }

  static async logout(): Promise<void> {
    try {
      await ApiService.post('/auth/logout');
    } catch (error) {
      console.warn('Logout API call failed:', error);
    } finally {
      // Clear stored data
      await AsyncStorage.multiRemove([this.TOKEN_KEY, this.USER_KEY]);
      ApiService.clearAuthToken();
    }
  }

  static async getCurrentUser(): Promise<User | null> {
    try {
      const token = await AsyncStorage.getItem(this.TOKEN_KEY);
      const userData = await AsyncStorage.getItem(this.USER_KEY);

      if (!token || !userData) {
        return null;
      }

      // Set API authorization header
      ApiService.setAuthToken(token);

      // Verify token is still valid
      const response = await ApiService.get('/auth/me');
      const user = response.data;

      // Update stored user data if it changed
      await AsyncStorage.setItem(this.USER_KEY, JSON.stringify(user));

      return user;
    } catch (error) {
      // Token is invalid, clear stored data
      await this.logout();
      return null;
    }
  }

  static async refreshToken(): Promise<string | null> {
    try {
      const response = await ApiService.post('/auth/refresh');
      const { token } = response.data;

      await AsyncStorage.setItem(this.TOKEN_KEY, token);
      ApiService.setAuthToken(token);

      return token;
    } catch (error) {
      await this.logout();
      return null;
    }
  }

  static async getStoredToken(): Promise<string | null> {
    return await AsyncStorage.getItem(this.TOKEN_KEY);
  }
}

// mobile/src/services/RealtimeService.ts
import io, { Socket } from 'socket.io-client';
import { AuthService } from './AuthService';
import { EventEmitter } from 'events';

export class RealtimeService extends EventEmitter {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private isConnecting = false;

  async connect(): Promise<void> {
    if (this.socket?.connected || this.isConnecting) {
      return;
    }

    this.isConnecting = true;

    try {
      const token = await AuthService.getStoredToken();
      if (!token) {
        throw new Error('No authentication token available');
      }

      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:4000';
      
      this.socket = io(`${apiUrl}/realtime`, {
        auth: { token },
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: this.maxReconnectAttempts,
        reconnectionDelay: 1000,
      });

      this.setupEventHandlers();
      
      return new Promise((resolve, reject) => {
        this.socket!.on('connect', () => {
          console.log('Connected to realtime server');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          this.emit('connected');
          resolve();
        });

        this.socket!.on('connect_error', (error) => {
          console.error('Realtime connection error:', error);
          this.isConnecting = false;
          this.emit('connection_error', error);
          reject(error);
        });
      });
    } catch (error) {
      this.isConnecting = false;
      throw error;
    }
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.emit('disconnected');
  }

  joinChannel(channelId: string): void {
    this.socket?.emit('join_channel', { channelId });
  }

  leaveChannel(channelId: string): void {
    this.socket?.emit('leave_channel', { channelId });
  }

  startTyping(channelId: string): void {
    this.socket?.emit('typing_start', { channelId });
  }

  stopTyping(channelId: string): void {
    this.socket?.emit('typing_stop', { channelId });
  }

  isConnected(): boolean {
    return this.socket?.connected || false;
  }

  private setupEventHandlers(): void {
    if (!this.socket) return;

    this.socket.on('disconnect', (reason) => {
      console.log('Disconnected from realtime server:', reason);
      this.emit('disconnected', reason);
    });

    this.socket.on('reconnect', (attemptNumber) => {
      console.log('Reconnected to realtime server after', attemptNumber, 'attempts');
      this.emit('reconnected');
    });

    this.socket.on('reconnect_error', (error) => {
      console.error('Reconnection error:', error);
      this.reconnectAttempts++;
    });

    // Task events
    this.socket.on('task_created', (task) => {
      this.emit('task:created', task);
    });

    this.socket.on('task_updated', (task) => {
      this.emit('task:updated', task);
    });

    this.socket.on('task_completed', (task) => {
      this.emit('task:completed', task);
    });

    // Message events
    this.socket.on('message_created', (message) => {
      this.emit('message:created', message);
    });

    // Notification events
    this.socket.on('notification', (notification) => {
      this.emit('notification:received', notification);
    });

    // Presence events
    this.socket.on('user_presence_updated', (data) => {
      this.emit('presence:updated', data);
    });

    this.socket.on('user_typing', (data) => {
      this.emit('typing:start', data);
    });

    this.socket.on('user_stopped_typing', (data) => {
      this.emit('typing:stop', data);
    });

    // Property events
    this.socket.on('rent_roll_anomaly', (data) => {
      this.emit('rentroll:anomaly', data);
    });

    this.socket.on('competitor_alert', (data) => {
      this.emit('competitor:alert', data);
    });

    // System events
    this.socket.on('system_maintenance', (data) => {
      this.emit('system:maintenance', data);
    });

    // Heartbeat
    this.socket.on('heartbeat_ack', () => {
      // Connection is alive
    });

    // Send heartbeat every 30 seconds
    setInterval(() => {
      if (this.socket?.connected) {
        this.socket.emit('heartbeat');
      }
    }, 30000);
  }
}

// Export singleton instance
export const realtimeService = new RealtimeService();

// mobile/src/services/NotificationService.ts
import PushNotification from 'react-native-push-notification';
import { Platform } from 'react-native';
import { ApiService } from './ApiService';

export class NotificationService {
  static async registerToken(token: string): Promise<void> {
    try {
      await ApiService.post('/notifications/register-device', {
        token,
        platform: Platform.OS,
        appVersion: '1.0.0', // From package.json
      });
    } catch (error) {
      console.error('Failed to register push token:', error);
    }
  }

  static handleNotification(notification: any): void {
    console.log('Handling notification:', notification);

    // Show local notification if app is in foreground
    if (notification.foreground) {
      PushNotification.localNotification({
        title: notification.title,
        message: notification.message,
        playSound: true,
        soundName: 'default',
        data: notification.data,
      });
    }

    // Handle notification action
    if (notification.action) {
      this.handleNotificationAction(notification.action, notification.data);
    }
  }

  static handleNotificationAction(action: string, data: any): void {
    switch (action) {
      case 'view_task':
        // Navigate to task detail
        console.log('Navigate to task:', data.taskId);
        break;
      case 'view_property':
        // Navigate to property detail
        console.log('Navigate to property:', data.propertyId);
        break;
      case 'open_chat':
        // Navigate to chat
        console.log('Open chat:', data.channelId);
        break;
      default:
        // Default action - open app
        break;
    }
  }

  static scheduleLocalNotification(
    title: string,
    message: string,
    date: Date,
    data?: any
  ): void {
    PushNotification.localNotificationSchedule({
      title,
      message,
      date,
      data: data || {},
      playSound: true,
      soundName: 'default',
    });
  }

  static cancelLocalNotification(id: string): void {
    PushNotification.cancelLocalNotifications({ id });
  }

  static clearAllNotifications(): void {
    PushNotification.cancelAllLocalNotifications();
  }

  static setBadgeCount(count: number): void {
    if (Platform.OS === 'ios') {
      PushNotification.setApplicationIconBadgeNumber(count);
    }
  }
}

// mobile/src/context/AuthContext.tsx
import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { AuthService, User } from '../services/AuthService';
import { realtimeService } from '../services/RealtimeService';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthState();
  }, []);

  const checkAuthState = async () => {
    try {
      const currentUser = await AuthService.getCurrentUser();
      setUser(currentUser);
      
      if (currentUser) {
        // Connect to realtime service
        try {
          await realtimeService.connect();
        } catch (error) {
          console.warn('Failed to connect to realtime service:', error);
        }
      }
    } catch (error) {
      console.error('Auth state check failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    try {
      const { user: loggedInUser } = await AuthService.login(email, password);
      setUser(loggedInUser);
      
      // Connect to realtime service
      await realtimeService.connect();
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      await AuthService.logout();
      realtimeService.disconnect();
      setUser(null);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const refreshUser = async () => {
    try {
      const currentUser = await AuthService.getCurrentUser();
      setUser(currentUser);
    } catch (error) {
      console.error('User refresh failed:', error);
      await logout();
    }
  };

  const value: AuthContextType = {
    user,
    loading,
    login,
    logout,
    refreshUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// mobile/src/context/RealtimeContext.tsx
import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { realtimeService } from '../services/RealtimeService';
import { useAuth } from './AuthContext';

interface RealtimeContextType {
  isConnected: boolean;
  joinChannel: (channelId: string) => void;
  leaveChannel: (channelId: string) => void;
  startTyping: (channelId: string) => void;
  stopTyping: (channelId: string) => void;
}

const RealtimeContext = createContext<RealtimeContextType | undefined>(undefined);

export const useRealtime = () => {
  const context = useContext(RealtimeContext);
  if (context === undefined) {
    throw new Error('useRealtime must be used within a RealtimeProvider');
  }
  return context;
};

interface RealtimeProviderProps {
  children: ReactNode;
}

export const RealtimeProvider: React.FC<RealtimeProviderProps> = ({ children }) => {
  const [isConnected, setIsConnected] = useState(false);
  const { user } = useAuth();

  useEffect(() => {
    if (user) {
      setupRealtimeListeners();
    } else {
      realtimeService.disconnect();
      setIsConnected(false);
    }

    return () => {
      realtimeService.removeAllListeners();
    };
  }, [user]);

  const setupRealtimeListeners = () => {
    realtimeService.on('connected', () => {
      setIsConnected(true);
    });

    realtimeService.on('disconnected', () => {
      setIsConnected(false);
    });

    realtimeService.on('reconnected', () => {
      setIsConnected(true);
    });

    realtimeService.on('connection_error', (error) => {
      console.error('Realtime connection error:', error);
      setIsConnected(false);
    });
  };

  const joinChannel = (channelId: string) => {
    realtimeService.joinChannel(channelId);
  };

  const leaveChannel = (channelId: string) => {
    realtimeService.leaveChannel(channelId);
  };

  const startTyping = (channelId: string) => {
    realtimeService.startTyping(channelId);
  };

  const stopTyping = (channelId: string) => {
    realtimeService.stopTyping(channelId);
  };

  const value: RealtimeContextType = {
    isConnected,
    joinChannel,
    leaveChannel,
    startTyping,
    stopTyping,
  };

  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>;
};