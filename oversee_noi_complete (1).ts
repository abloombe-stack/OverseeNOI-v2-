// =====================================================
// NOTIFICATION SERVICE
// =====================================================

// src/notification/notification.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import * as webpush from 'web-push';
import * as nodemailer from 'nodemailer';

interface NotificationPayload {
  userId: string;
  type: string;
  title: string;
  message: string;
  data?: any;
  priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  channels?: ('push' | 'email' | 'sms')[];
}

@Injectable()
export class NotificationService {
  private readonly logger = new Logger(NotificationService.name);
  private emailTransporter: nodemailer.Transporter;

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
    private eventEmitter: EventEmitter2,
  ) {
    this.setupWebPush();
    this.setupEmailTransporter();
  }

  private setupWebPush(): void {
    webpush.setVapidDetails(
      'mailto:support@oversee-noi.com',
      this.configService.get<string>('VAPID_PUBLIC_KEY'),
      this.configService.get<string>('VAPID_PRIVATE_KEY'),
    );
  }

  private setupEmailTransporter(): void {
    this.emailTransporter = nodemailer.createTransporter({
      host: this.configService.get<string>('SMTP_HOST'),
      port: this.configService.get<number>('SMTP_PORT'),
      secure: this.configService.get<boolean>('SMTP_SECURE'),
      auth: {
        user: this.configService.get<string>('SMTP_USER'),
        pass: this.configService.get<string>('SMTP_PASS'),
      },
    });
  }

  async send(payload: NotificationPayload): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: payload.userId },
      include: { company: true },
    });

    if (!user) {
      this.logger.warn(`User not found for notification: ${payload.userId}`);
      return;
    }

    const preferences = await this.getUserNotificationPreferences(payload.userId);
    const enabledChannels = payload.channels || this.getDefaultChannels(payload.type);

    // Store notification in database
    const notification = await this.prisma.notification.create({
      data: {
        userId: payload.userId,
        type: payload.type,
        title: payload.title,
        message: payload.message,
        data: payload.data || {},
        priority: payload.priority || 'MEDIUM',
        channels: enabledChannels,
      },
    });

    // Send via enabled channels
    const sendPromises = enabledChannels.map(async (channel) => {
      if (!preferences[channel]?.enabled) return;

      try {
        switch (channel) {
          case 'push':
            await this.sendPushNotification(user, payload);
            break;
          case 'email':
            await this.sendEmailNotification(user, payload);
            break;
          case 'sms':
            await this.sendSMSNotification(user, payload);
            break;
        }
        
        await this.prisma.notificationDelivery.create({
          data: {
            notificationId: notification.id,
            channel,
            status: 'DELIVERED',
            deliveredAt: new Date(),
          },
        });
      } catch (error) {
        this.logger.error(`Failed to send ${channel} notification:`, error);
        
        await this.prisma.notificationDelivery.create({
          data: {
            notificationId: notification.id,
            channel,
            status: 'FAILED',
            error: error.message,
          },
        });
      }
    });

    await Promise.allSettled(sendPromises);

    // Emit event for real-time updates
    this.eventEmitter.emit('notification.sent', {
      userId: payload.userId,
      notification,
    });
  }

  private async sendPushNotification(user: any, payload: NotificationPayload): Promise<void> {
    const subscriptions = await this.prisma.pushSubscription.findMany({
      where: { userId: user.id, active: true },
    });

    const pushPayload = {
      title: payload.title,
      body: payload.message,
      icon: '/icons/notification-icon.png',
      badge: '/icons/badge-icon.png',
      data: {
        type: payload.type,
        ...payload.data,
      },
      actions: this.getPushActions(payload.type),
    };

    const pushPromises = subscriptions.map(async (subscription) => {
      try {
        await webpush.sendNotification(
          {
            endpoint: subscription.endpoint,
            keys: {
              p256dh: subscription.p256dh,
              auth: subscription.auth,
            },
          },
          JSON.stringify(pushPayload),
        );
      } catch (error) {
        if (error.statusCode === 410) {
          // Subscription expired, remove it
          await this.prisma.pushSubscription.delete({
            where: { id: subscription.id },
          });
        }
        throw error;
      }
    });

    await Promise.all(pushPromises);
  }

  private async sendEmailNotification(user: any, payload: NotificationPayload): Promise<void> {
    const template = await this.getEmailTemplate(payload.type);
    
    const mailOptions = {
      from: `"OverseeNOI" <notifications@oversee-noi.com>`,
      to: user.email,
      subject: payload.title,
      html: this.renderEmailTemplate(template, {
        user,
        payload,
        companyName: user.company.name,
        unsubscribeUrl: `${this.configService.get('APP_URL')}/unsubscribe/${user.id}`,
      }),
    };

    await this.emailTransporter.sendMail(mailOptions);
  }

  private async sendSMSNotification(user: any, payload: NotificationPayload): Promise<void> {
    // Implementation would depend on SMS provider (Twilio, AWS SNS, etc.)
    // For now, log that SMS would be sent
    this.logger.log(`SMS notification would be sent to ${user.phone}: ${payload.message}`);
  }

  private getPushActions(type: string): any[] {
    const actions = {
      TASK_ASSIGNED: [
        { action: 'view', title: 'View Task' },
        { action: 'dismiss', title: 'Dismiss' },
      ],
      RENT_ANOMALY: [
        { action: 'investigate', title: 'Investigate' },
        { action: 'dismiss', title: 'Dismiss' },
      ],
      COMPETITOR_ALERT: [
        { action: 'view_analysis', title: 'View Analysis' },
        { action: 'dismiss', title: 'Dismiss' },
      ],
    };

    return actions[type] || [{ action: 'dismiss', title: 'Dismiss' }];
  }

  private async getUserNotificationPreferences(userId: string): Promise<any> {
    const preferences = await this.prisma.notificationPreference.findFirst({
      where: { userId },
    });

    return preferences?.preferences || {
      push: { enabled: true },
      email: { enabled: true },
      sms: { enabled: false },
    };
  }

  private getDefaultChannels(type: string): string[] {
    const channelMap = {
      TASK_ASSIGNED: ['push', 'email'],
      TASK_DUE: ['push'],
      RENT_ANOMALY: ['push', 'email'],
      COMPETITOR_ALERT: ['push'],
      SYSTEM_ALERT: ['push', 'email'],
    };

    return channelMap[type] || ['push'];
  }

  private async getEmailTemplate(type: string): Promise<string> {
    // In production, templates would be stored in database or files
    const templates = {
      TASK_ASSIGNED: `
        <h2>New Task Assigned</h2>
        <p>You have been assigned a new task: <strong>{{payload.title}}</strong></p>
        <p>{{payload.message}}</p>
        <a href="{{appUrl}}/tasks/{{payload.data.taskId}}" style="background: #3b82f6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Task</a>
      `,
      RENT_ANOMALY: `
        <h2>Rent Roll Anomaly Detected</h2>
        <p>{{payload.message}}</p>
        <a href="{{appUrl}}/properties/{{payload.data.propertyId}}/rent-roll" style="background: #ef4444; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Investigate</a>
      `,
    };

    return templates[type] || '<p>{{payload.message}}</p>';
  }

  private renderEmailTemplate(template: string, data: any): string {
    let rendered = template;
    
    // Simple template rendering - in production, use a proper template engine
    rendered = rendered.replace(/\{\{user\.name\}\}/g, data.user.displayName);
    rendered = rendered.replace(/\{\{payload\.title\}\}/g, data.payload.title);
    rendered = rendered.replace(/\{\{payload\.message\}\}/g, data.payload.message);
    rendered = rendered.replace(/\{\{companyName\}\}/g, data.companyName);
    rendered = rendered.replace(/\{\{appUrl\}\}/g, this.configService.get('APP_URL'));
    rendered = rendered.replace(/\{\{unsubscribeUrl\}\}/g, data.unsubscribeUrl);

    // Replace nested data properties
    if (data.payload.data) {
      Object.entries(data.payload.data).forEach(([key, value]) => {
        const regex = new RegExp(`\\{\\{payload\\.data\\.${key}\\}\\}`, 'g');
        rendered = rendered.replace(regex, String(value));
      });
    }

    return rendered;
  }

  // Real-time notification gateway for WebSocket connections
  async sendRealtime(userId: string, notification: any): Promise<void> {
    this.eventEmitter.emit('notification.realtime', {
      userId,
      notification,
    });
  }

  // Bulk notification methods
  async sendBulk(userIds: string[], payload: Omit<NotificationPayload, 'userId'>): Promise<void> {
    const promises = userIds.map(userId => 
      this.send({ ...payload, userId })
    );
    
    await Promise.allSettled(promises);
  }

  async sendToRole(role: string, propertyId: string, payload: Omit<NotificationPayload, 'userId'>): Promise<void> {
    const users = await this.prisma.user.findMany({
      where: {
        roles: {
          some: {
            role,
            OR: [
              { propertyId },
              { propertyId: null }, // Company-wide roles
            ],
          },
        },
      },
    });

    await this.sendBulk(users.map(u => u.id), payload);
  }
}

// =====================================================
// FILE MANAGEMENT SERVICE
// =====================================================

// src/files/files.service.ts
import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import * as AWS from 'aws-sdk';
import * as crypto from 'crypto';
import * as path from 'path';
import * as sharp from 'sharp';
import * as ClamScan from 'clamscan';

interface UploadOptions {
  userId: string;
  propertyId?: string;
  taskId?: string;
  maxSize?: number;
  allowedTypes?: string[];
  generateThumbnail?: boolean;
}

@Injectable()
export class FilesService {
  private readonly logger = new Logger(FilesService.name);
  private s3: AWS.S3;
  private clamscan: ClamScan;

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {
    this.s3 = new AWS.S3({
      region: this.configService.get('AWS_REGION'),
      accessKeyId: this.configService.get('AWS_ACCESS_KEY_ID'),
      secretAccessKey: this.configService.get('AWS_SECRET_ACCESS_KEY'),
    });

    this.initVirusScanner();
  }

  private async initVirusScanner(): Promise<void> {
    try {
      this.clamscan = await new ClamScan().init({
        removeInfected: false,
        quarantineInfected: false,
        debugMode: false,
      });
    } catch (error) {
      this.logger.warn('ClamAV not available, virus scanning disabled');
    }
  }

  async uploadFile(
    file: Express.Multer.File,
    options: UploadOptions,
  ): Promise<any> {
    // Validate file
    this.validateFile(file, options);

    // Virus scan
    if (this.clamscan) {
      const scanResult = await this.clamscan.scanBuffer(file.buffer);
      if (scanResult.isInfected) {
        throw new BadRequestException('File contains malware');
      }
    }

    // Generate unique filename
    const fileExtension = path.extname(file.originalname);
    const fileName = `${crypto.randomUUID()}${fileExtension}`;
    const s3Key = this.generateS3Key(options, fileName);

    // Upload to S3
    const uploadParams: AWS.S3.PutObjectRequest = {
      Bucket: this.configService.get('S3_BUCKET'),
      Key: s3Key,
      Body: file.buffer,
      ContentType: file.mimetype,
      Metadata: {
        originalName: file.originalname,
        uploadedBy: options.userId,
        propertyId: options.propertyId || '',
        taskId: options.taskId || '',
      },
    };

    const uploadResult = await this.s3.upload(uploadParams).promise();

    // Generate thumbnail for images
    let thumbnailUrl: string | null = null;
    if (options.generateThumbnail && this.isImage(file.mimetype)) {
      thumbnailUrl = await this.generateThumbnail(file.buffer, s3Key);
    }

    // Save file metadata to database
    const fileRecord = await this.prisma.file.create({
      data: {
        filename: fileName,
        originalName: file.originalname,
        mimeType: file.mimetype,
        size: file.size,
        s3Key,
        s3Url: uploadResult.Location,
        thumbnailUrl,
        uploadedById: options.userId,
        propertyId: options.propertyId,
        taskId: options.taskId,
        metadata: {
          checksum: crypto.createHash('md5').update(file.buffer).digest('hex'),
          uploadedAt: new Date(),
        },
      },
    });

    return fileRecord;
  }

  async getSignedUrl(fileId: string, userId: string): Promise<string> {
    const file = await this.prisma.file.findUnique({
      where: { id: fileId },
      include: {
        property: true,
        task: { include: { channel: true } },
      },
    });

    if (!file) {
      throw new BadRequestException('File not found');
    }

    // Check permissions
    await this.validateFileAccess(file, userId);

    // Generate signed URL for temporary access
    const signedUrl = this.s3.getSignedUrl('getObject', {
      Bucket: this.configService.get('S3_BUCKET'),
      Key: file.s3Key,
      Expires: 3600, // 1 hour
    });

    return signedUrl;
  }

  async deleteFile(fileId: string, userId: string): Promise<void> {
    const file = await this.prisma.file.findUnique({
      where: { id: fileId },
      include: { property: true },
    });

    if (!file) {
      throw new BadRequestException('File not found');
    }

    // Check permissions (only uploader or admin can delete)
    await this.validateFileAccess(file, userId);

    // Delete from S3
    await this.s3.deleteObject({
      Bucket: this.configService.get('S3_BUCKET'),
      Key: file.s3Key,
    }).promise();

    // Delete thumbnail if exists
    if (file.thumbnailUrl) {
      const thumbnailKey = file.s3Key.replace(/(\.[^.]+)$/, '_thumb$1');
      await this.s3.deleteObject({
        Bucket: this.configService.get('S3_BUCKET'),
        Key: thumbnailKey,
      }).promise();
    }

    // Delete from database
    await this.prisma.file.delete({
      where: { id: fileId },
    });
  }

  private validateFile(file: Express.Multer.File, options: UploadOptions): void {
    const maxSize = options.maxSize || 10 * 1024 * 1024; // 10MB default
    const allowedTypes = options.allowedTypes || [
      'image/jpeg',
      'image/png',
      'image/gif',
      'application/pdf',
      'text/csv',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ];

    if (file.size > maxSize) {
      throw new BadRequestException(`File size exceeds ${maxSize / 1024 / 1024}MB limit`);
    }

    if (!allowedTypes.includes(file.mimetype)) {
      throw new BadRequestException('File type not allowed');
    }
  }

  private generateS3Key(options: UploadOptions, fileName: string): string {
    const prefix = options.propertyId 
      ? `properties/${options.propertyId}`
      : 'general';
    
    const subfolder = options.taskId ? `tasks/${options.taskId}` : 'files';
    
    return `${prefix}/${subfolder}/${fileName}`;
  }

  private async generateThumbnail(buffer: Buffer, originalKey: string): Promise<string> {
    const thumbnailBuffer = await sharp(buffer)
      .resize(300, 300, { fit: 'inside', withoutEnlargement: true })
      .jpeg({ quality: 80 })
      .toBuffer();

    const thumbnailKey = originalKey.replace(/(\.[^.]+)$/, '_thumb.jpg');

    const uploadParams: AWS.S3.PutObjectRequest = {
      Bucket: this.configService.get('S3_BUCKET'),
      Key: thumbnailKey,
      Body: thumbnailBuffer,
      ContentType: 'image/jpeg',
    };

    const result = await this.s3.upload(uploadParams).promise();
    return result.Location;
  }

  private isImage(mimeType: string): boolean {
    return mimeType.startsWith('image/');
  }

  private async validateFileAccess(file: any, userId: string): Promise<void> {
    // Implementation would check RBAC permissions
    // For now, simplified check
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { roles: true },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // File uploader can always access
    if (file.uploadedById === userId) {
      return;
    }

    // Check property access through RBAC
    if (file.propertyId) {
      const hasAccess = user.roles.some(role => 
        role.propertyId === file.propertyId || role.propertyId === null
      );

      if (!hasAccess) {
        throw new BadRequestException('Insufficient permissions to access file');
      }
    }
  }
}

// =====================================================
// TESTING EXAMPLES
// =====================================================

// backend/test/tasks/tasks.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { TasksService } from '../../src/tasks/tasks.service';
import { PrismaService } from '../../src/prisma/prisma.service';
import { AIService } from '../../src/ai/ai.service';
import { NotificationService } from '../../src/notification/notification.service';
import { RBACService } from '../../src/auth/rbac.service';

describe('TasksService', () => {
  let service: TasksService;
  let prismaService: PrismaService;

  const mockPrismaService = {
    task: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    },
    channel: {
      findUnique: jest.fn(),
    },
    taskEvent: {
      create: jest.fn(),
    },
  };

  const mockAIService = {
    generateTaskSuggestions: jest.fn(),
    generateTaskSummary: jest.fn(),
  };

  const mockNotificationService = {
    send: jest.fn(),
  };

  const mockRBACService = {
    canAccessProperty: jest.fn().mockResolvedValue(true),
    canCreateTask: jest.fn().mockResolvedValue(true),
    canCompleteTask: jest.fn().mockResolvedValue(true),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TasksService,
        { provide: PrismaService, useValue: mockPrismaService },
        { provide: AIService, useValue: mockAIService },
        { provide: NotificationService, useValue: mockNotificationService },
        { provide: RBACService, useValue: mockRBACService },
      ],
    }).compile();

    service = module.get<TasksService>(TasksService);
    prismaService = module.get<PrismaService>(PrismaService);
  });

  describe('findByChannel', () => {
    it('should return tasks for a channel', async () => {
      const mockTasks = [
        {
          id: 'task1',
          title: 'Test Task',
          status: 'OPEN',
          priority: 'HIGH',
          channelId: 'channel1',
        },
      ];

      const mockChannel = {
        id: 'channel1',
        propertyId: 'property1',
        key: 'leasing',
      };

      mockPrismaService.channel.findUnique.mockResolvedValue(mockChannel);
      mockPrismaService.task.findMany.mockResolvedValue(mockTasks);

      const result = await service.findByChannel('channel1', {}, { id: 'user1' });

      expect(result).toEqual(mockTasks);
      expect(mockPrismaService.channel.findUnique).toHaveBeenCalledWith({
        where: { id: 'channel1' },
        include: { property: true },
      });
    });

    it('should throw error if user lacks permissions', async () => {
      const mockChannel = {
        id: 'channel1',
        propertyId: 'property1',
      };

      mockPrismaService.channel.findUnique.mockResolvedValue(mockChannel);
      mockRBACService.canAccessProperty.mockResolvedValue(false);

      await expect(
        service.findByChannel('channel1', {}, { id: 'user1' })
      ).rejects.toThrow('Insufficient permissions');
    });
  });

  describe('create', () => {
    it('should create a new task', async () => {
      const taskInput = {
        title: 'New Task',
        description: 'Task description',
        channelId: 'channel1',
        priority: 'MEDIUM' as const,
      };

      const mockChannel = {
        id: 'channel1',
        propertyId: 'property1',
        key: 'leasing',
        property: { id: 'property1', name: 'Test Property' },
      };

      const mockCreatedTask = {
        id: 'task1',
        ...taskInput,
        createdById: 'user1',
        status: 'OPEN',
        createdAt: new Date(),
      };

      mockPrismaService.channel.findUnique.mockResolvedValue(mockChannel);
      mockPrismaService.task.create.mockResolvedValue(mockCreatedTask);

      const result = await service.create(taskInput, { id: 'user1' });

      expect(result).toEqual(mockCreatedTask);
      expect(mockPrismaService.task.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          ...taskInput,
          createdById: 'user1',
        }),
        include: expect.any(Object),
      });
    });
  });
});

// =====================================================
// SEED DATA
// =====================================================

// backend/prisma/seed.ts
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Create companies
  const company1 = await prisma.company.create({
    data: {
      name: 'Premium Asset Management',
      settings: {
        timezone: 'America/New_York',
        features: ['ai_assistant', 'competitor_tracking', 'binoculars'],
      },
    },
  });

  const company2 = await prisma.company.create({
    data: {
      name: 'Metro Property Group',
      settings: {
        timezone: 'America/Chicago',
        features: ['ai_assistant', 'rent_roll_diff'],
      },
    },
  });

  // Create portfolios
  const portfolio1 = await prisma.portfolio.create({
    data: {
      name: 'Texas Portfolio',
      companyId: company1.id,
    },
  });

  const portfolio2 = await prisma.portfolio.create({
    data: {
      name: 'Florida Portfolio',
      companyId: company1.id,
    },
  });

  // Create properties
  const properties = await Promise.all([
    prisma.property.create({
      data: {
        name: 'Sunset Gardens',
        address: '123 Main Street, Austin, TX 78701',
        unitCount: 245,
        propertyType: 'Multifamily',
        portfolioId: portfolio1.id,
      },
    }),
    prisma.property.create({
      data: {
        name: 'Metro Heights',
        address: '456 Downtown Blvd, Austin, TX 78702',
        unitCount: 180,
        propertyType: 'Multifamily',
        portfolioId: portfolio1.id,
      },
    }),
    prisma.property.create({
      data: {
        name: 'Ocean View Apartments',
        address: '789 Beach Drive, Miami, FL 33139',
        unitCount: 320,
        propertyType: 'Luxury',
        portfolioId: portfolio2.id,
      },
    }),
  ]);

  // Create users with different roles
  const users = await Promise.all([
    // Asset Management Company Users
    prisma.user.create({
      data: {
        email: 'sarah.johnson@premium-am.com',
        displayName: 'Sarah Johnson',
        companyId: company1.id,
      },
    }),
    prisma.user.create({
      data: {
        email: 'mike.chen@premium-am.com',
        displayName: 'Mike Chen',
        companyId: company1.id,
      },
    }),
    // Property Management Company Users
    prisma.user.create({
      data: {
        email: 'lisa.rodriguez@metro-pm.com',
        displayName: 'Lisa Rodriguez',
        companyId: company1.id, // Same company, different roles
      },
    }),
    prisma.user.create({
      data: {
        email: 'david.kim@metro-pm.com',
        displayName: 'David Kim',
        companyId: company1.id,
      },
    }),
    prisma.user.create({
      data: {
        email: 'anna.white@metro-pm.com',
        displayName: 'Anna White',
        companyId: company1.id,
      },
    }),
  ]);

  // Create user roles
  await Promise.all([
    // Sarah - Asset Manager with access to all properties
    prisma.userRole.create({
      data: {
        userId: users[0].id,
        role: 'ASSET_MANAGER',
        scope: { allProperties: true },
      },
    }),
    // Mike - Senior Analyst for Texas Portfolio
    prisma.userRole.create({
      data: {
        userId: users[1].id,
        propertyId: properties[0].id,
        role: 'SENIOR_ANALYST',
        scope: { properties: [properties[0].id, properties[1].id] },
      },
    }),
    // Lisa - Regional PM for Texas
    prisma.userRole.create({
      data: {
        userId: users[2].id,
        role: 'REGIONAL_PM',
        scope: { portfolio: portfolio1.id },
      },
    }),
    // David - Property Manager for Sunset Gardens
    prisma.userRole.create({
      data: {
        userId: users[3].id,
        propertyId: properties[0].id,
        role: 'PROPERTY_MANAGER',
        scope: { properties: [properties[0].id] },
      },
    }),
    // Anna - Leasing Manager for Sunset Gardens
    prisma.userRole.create({
      data: {
        userId: users[4].id,
        propertyId: properties[0].id,
        role: 'LEASING_MANAGER',
        scope: { properties: [properties[0].id] },
      },
    }),
  ]);

  // Create channels for each property
  const channels = [];
  for (const property of properties) {
    const propertyChannels = await Promise.all([
      prisma.channel.create({
        data: {
          key: 'leasing',
          name: 'Leasing',
          propertyId: property.id,
          visibilityRoles: ['ASSET_MANAGER', 'REGIONAL_PM', 'PROPERTY_MANAGER', 'LEASING_MANAGER', 'LEASING_AGENT'],
        },
      }),
      prisma.channel.create({
        data: {
          key: 'maintenance',
          name: 'Maintenance',
          propertyId: property.id,
          visibilityRoles: ['ASSET_MANAGER', 'REGIONAL_PM', 'PROPERTY_MANAGER', 'MAINTENANCE_SUPER', 'MAINTENANCE_TECH'],
        },
      }),
      prisma.channel.create({
        data: {
          key: 'ar',
          name: 'AR & Collections',
          propertyId: property.id,
          visibilityRoles: ['ASSET_MANAGER', 'REGIONAL_PM', 'PROPERTY_MANAGER', 'ASSISTANT_PM_AR'],
        },
      }),
      prisma.channel.create({
        data: {
          key: 'capex',
          name: 'CapEx Projects',
          propertyId: property.id,
          visibilityRoles: ['ASSET_MANAGER', 'CAPEX_PM', 'REGIONAL_PM', 'PROPERTY_MANAGER'],
        },
      }),
    ]);
    channels.push(...propertyChannels);
  }

  // Create sample tasks
  const tasks = await Promise.all([
    prisma.task.create({
      data: {
        title: 'Review Q3 rent roll anomalies',
        description: 'Several units showing unusual balance changes that need investigation. Focus on units 245A, 156B, and 302C.',
        status: 'OPEN',
        priority: 'HIGH',
        channelId: channels.find(c => c.key === 'ar' && c.propertyId === properties[0].id)?.id,
        assigneeId: users[3].id, // David (Property Manager)
        createdById: users[0].id, // Sarah (Asset Manager)
        dueAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000), // 2 days from now
        tags: ['rent-roll', 'anomaly', 'urgent'],
      },
    }),
    prisma.task.create({
      data: {
        title: 'Update market rents based on competitor analysis',
        description: 'Recent competitor analysis shows opportunity to increase 2BR rents by $75/month. Need to review and implement.',
        status: 'IN_PROGRESS',
        priority: 'MEDIUM',
        channelId: channels.find(c => c.key === 'leasing' && c.propertyId === properties[0].id)?.id,
        assigneeId: users[4].id, // Anna (Leasing Manager)
        createdById: users[1].id, // Mike (Senior Analyst)
        dueAt: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000), // 5 days from now
        tags: ['pricing', 'competitor-analysis', 'revenue'],
      },
    }),
    prisma.task.create({
      data: {
        title: 'HVAC preventive maintenance - Building C',
        description: 'Quarterly HVAC maintenance due for Building C units. Schedule and coordinate with residents.',
        status: 'SCHEDULED',
        priority: 'MEDIUM',
        channelId: channels.find(c => c.key === 'maintenance' && c.propertyId === properties[1].id)?.id,
        createdById: users[2].id, // Lisa (Regional PM)
        dueAt: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), // 3 days from now
        tags: ['preventive-maintenance', 'hvac', 'scheduled'],
      },
    }),
  ]);

  // Create sample messages
  await Promise.all([
    prisma.message.create({
      data: {
        content: 'Anomaly detected: Unit 245A balance increased by $1,247 without corresponding payment. Possible data entry error or missed adjustment.',
        channelId: channels.find(c => c.key === 'ar')?.id,
        taskId: tasks[0].id,
        authorId: 'system',
        isSystem: true,
      },
    }),
    prisma.message.create({
      data: {
        content: '@David can you check if this is related to the deposit adjustment we discussed last week?',
        channelId: channels.find(c => c.key === 'ar')?.id,
        taskId: tasks[0].id,
        authorId: users[0].id, // Sarah
        isSystem: false,
      },
    }),
    prisma.message.create({
      data: {
        content: 'I\'ll review the transaction history and get back to you by tomorrow.',
        channelId: channels.find(c => c.key === 'ar')?.id,
        taskId: tasks[0].id,
        authorId: users[3].id, // David
        isSystem: false,
      },
    }),
  ]);

  // Create sample rent roll snapshot
  const sampleUnits = Array.from({ length: 20 }, (_, i) => ({
    unit_id: `${100 + i}A`,
    unit_label: `${100 + i}A`,
    building: 'A',
    floorplan: i % 3 === 0 ? 'Studio' : i % 3 === 1 ? '1BR/1BA' : '2BR/2BA',
    bedrooms: i % 3,
    bathrooms: i % 3 === 0 ? 1 : i % 3,
    sqft: i % 3 === 0 ? 650 : i % 3 === 1 ? 850 : 1200,
    tenant_name_masked: i % 4 === 0 ? null : `J*** D**`,
    lease_start: i % 4 === 0 ? null : new Date('2024-01-01'),
    lease_end: i % 4 === 0 ? null : new Date('2024-12-31'),
    market_rent: i % 3 === 0 ? 1800 : i % 3 === 1 ? 2200 : 2800,
    actual_rent: i % 3 === 0 ? 1750 : i % 3 === 1 ? 2150 : 2750,
    balance: Math.random() > 0.8 ? Math.floor(Math.random() * 2000) : 0,
    status: i % 4 === 0 ? 'vacant' : 'occupied',
    delinquency_bucket: '0',
  }));

  await prisma.rentRollSnapshot.create({
    data: {
      propertyId: properties[0].id,
      date: new Date(),
      units: sampleUnits,
      aggregates: {
        total_units: sampleUnits.length,
        occupied_units: sampleUnits.filter(u => u.status === 'occupied').length,
        total_balance: sampleUnits.reduce((sum, u) => sum + u.balance, 0),
        total_market_rent: sampleUnits.reduce((sum, u) => sum + u.market_rent, 0),
        total_actual_rent: sampleUnits.reduce((sum, u) => sum + u.actual_rent, 0),
      },
    },
  });

  console.log('✅ Database seeded successfully!');
  console.log(`Created:`);
  console.log(`  - ${2} companies`);
  console.log(`  - ${2} portfolios`);
  console.log(`  - ${properties.length} properties`);
  console.log(`  - ${users.length} users`);
  console.log(`  - ${channels.length} channels`);
  console.log(`  - ${tasks.length} tasks`);
  console.log(`  - Sample rent roll data`);
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });

// =====================================================
// SETUP INSTRUCTIONS
// =====================================================

/*
# OverseeNOI Setup Instructions

## Prerequisites
- Node.js 18+
- Docker & Docker Compose
- AWS CLI configured
- Terraform 1.6+

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/oversee-noi.git
cd oversee-noi
```

2. Install dependencies:
```bash
# Root level
npm install

# Frontend
cd frontend && npm install && cd ..

# Backend
cd backend && npm install && cd ..

# Extension
cd extension && npm install && cd ..
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Start development environment:
```bash
npm run dev
```

5. Run database migrations:
```bash
npm run migrate
```

6. Seed the database:
```bash
npm run seed
```

7. Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:4000
- GraphQL Playground: http://localhost:4000/graphql
- Database Studio: http://localhost:5555

## Production Deployment

1. Build Docker images:
```bash
npm run build
```

2. Deploy infrastructure:
```bash
cd terraform
terraform init
terraform plan -var-file=production.tfvars
terraform apply -var-file=production.tfvars
```

3. Deploy application:
```bash
# CI/CD pipeline will handle this automatically
# Or manually:
./scripts/deploy.sh production
```

## Environment Variables

### Backend (.env)
```
NODE_ENV=development
DATABASE_URL=postgresql://oversee:password@localhost:5432/oversee_dev
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-jwt-secret
OPENAI_API_KEY=your-openai-key
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AWS_REGION=us-east-1
S3_BUCKET=oversee-noi-files
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=your-sendgrid-key
VAPID_PUBLIC_KEY=your-vapid-public-key
VAPID_PRIVATE_KEY=your-vapid-private-key
```

### Frontend (.env.local)
```
NEXT_PUBLIC_API_URL=http://localhost:4000
NEXT_PUBLIC_WS_URL=ws://localhost:4000
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

## Testing

Run all tests:
```bash
npm test
```

Run specific test suites:
```bash
npm run test:backend
npm run test:frontend
npm run test:e2e
```

## Browser Extension Development

1. Build extension:
```bash
cd extension
npm run build
```

2. Load in Chrome:
- Open chrome://extensions/
- Enable Developer mode
- Click "Load unpacked"
- Select extension/dist folder

## Monitoring

- Application logs: CloudWatch
- Metrics: DataDog dashboard
- Errors: Sentry
- Uptime: StatusPage

## Support

For issues and questions:
- Documentation: https://docs.oversee-noi.com
- Support: support@oversee-noi.com
- Slack: #oversee-noi-support

*/