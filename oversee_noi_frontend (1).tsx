import React, { useState, useEffect } from 'react';
import { 
  Building2, MessageSquare, CheckCircle, Clock, AlertTriangle,
  Users, DollarSign, Settings, Plus, Search, Bell, Upload,
  Mic, Camera, Filter, MoreVertical, MapPin, Calendar
} from 'lucide-react';

// Mock data
const mockUser = {
  id: 'user1',
  name: 'Sarah Johnson',
  role: 'asset_manager',
  company: 'Premium Asset Management',
  avatar: '/api/placeholder/32/32'
};

const mockProperties = [
  {
    id: 'prop1',
    name: 'Sunset Gardens',
    address: '123 Main St, Austin, TX',
    unitCount: 245,
    portfolio: 'Texas Portfolio',
    channels: [
      { id: 'ch1', key: 'leasing', name: 'Leasing', unread: 3, lastActivity: '2m ago' },
      { id: 'ch2', key: 'maintenance', name: 'Maintenance', unread: 1, lastActivity: '15m ago' },
      { id: 'ch3', key: 'ar', name: 'AR & Collections', unread: 0, lastActivity: '1h ago' },
      { id: 'ch4', key: 'capex', name: 'CapEx Projects', unread: 2, lastActivity: '30m ago' },
    ]
  },
  {
    id: 'prop2',
    name: 'Metro Heights',
    address: '456 Downtown Blvd, Austin, TX',
    unitCount: 180,
    portfolio: 'Texas Portfolio',
    channels: [
      { id: 'ch5', key: 'leasing', name: 'Leasing', unread: 1, lastActivity: '5m ago' },
      { id: 'ch6', key: 'maintenance', name: 'Maintenance', unread: 0, lastActivity: '45m ago' },
      { id: 'ch7', key: 'ar', name: 'AR & Collections', unread: 0, lastActivity: '2h ago' },
    ]
  }
];

const mockTasks = [
  {
    id: 'task1',
    title: 'Review rent roll anomalies',
    description: 'Several units showing unusual balance changes that need investigation',
    status: 'open',
    priority: 'high',
    assignee: 'Mike Chen',
    dueDate: '2025-08-12',
    channel: 'ar',
    property: 'Sunset Gardens',
    messages: [
      {
        id: 'msg1',
        author: 'System',
        content: 'Anomaly detected: Unit 245A balance increased by $1,247 without corresponding payment',
        timestamp: '10:30 AM',
        isSystem: true
      },
      {
        id: 'msg2',
        author: 'Sarah Johnson',
        content: '@Mike can you check if this is related to the deposit adjustment we discussed?',
        timestamp: '10:35 AM',
        isSystem: false
      }
    ]
  },
  {
    id: 'task2',
    title: 'Update market rents based on competitor analysis',
    description: 'Competitor pricing analysis suggests we can increase 2BR rents by $75/month',
    status: 'in_progress',
    priority: 'medium',
    assignee: 'Lisa Park',
    dueDate: '2025-08-15',
    channel: 'leasing',
    property: 'Sunset Gardens',
    messages: [
      {
        id: 'msg3',
        author: 'AI Assistant',
        content: 'Analysis complete: Nearby properties increased 2BR rates by avg $82/month. Recommend $75 increase.',
        timestamp: '9:15 AM',
        isSystem: true
      }
    ]
  },
  {
    id: 'task3',
    title: 'HVAC maintenance - Building C',
    description: 'Preventive maintenance on HVAC units in Building C due this week',
    status: 'scheduled',
    priority: 'medium',
    assignee: 'Tony Martinez',
    dueDate: '2025-08-13',
    channel: 'maintenance',
    property: 'Metro Heights',
    messages: []
  }
];

const mockNotifications = [
  { id: 'n1', type: 'rent_anomaly', message: 'New delinquency detected in Sunset Gardens', time: '5m ago' },
  { id: 'n2', type: 'competitor_alert', message: 'Competitor reduced 1BR rates by $50', time: '15m ago' },
  { id: 'n3', type: 'task_due', message: 'HVAC maintenance task due tomorrow', time: '1h ago' }
];

function OverseeNOI() {
  const [selectedProperty, setSelectedProperty] = useState(mockProperties[0]);
  const [selectedChannel, setSelectedChannel] = useState(mockProperties[0].channels[0]);
  const [selectedTask, setSelectedTask] = useState(null);
  const [newMessage, setNewMessage] = useState('');
  const [showNotifications, setShowNotifications] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const channelTasks = mockTasks.filter(task => 
    task.channel === selectedChannel.key && task.property === selectedProperty.name
  );

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'high': return 'text-red-600 bg-red-50 border-red-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default: return 'text-green-600 bg-green-50 border-green-200';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-600" />;
      case 'in_progress': return <Clock className="w-4 h-4 text-blue-600" />;
      default: return <AlertTriangle className="w-4 h-4 text-gray-400" />;
    }
  };

  return (
    <div className="h-screen flex bg-gray-50">
      {/* Sidebar */}
      <div className="w-80 bg-white border-r border-gray-200 flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-gray-200">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <Building2 className="w-8 h-8 text-blue-600" />
              <div>
                <h1 className="text-lg font-bold text-gray-900">OverseeNOI</h1>
                <p className="text-sm text-gray-500">{mockUser.company}</p>
              </div>
            </div>
            <div className="relative">
              <button 
                onClick={() => setShowNotifications(!showNotifications)}
                className="p-2 rounded-lg hover:bg-gray-100 relative"
              >
                <Bell className="w-5 h-5 text-gray-600" />
                <span className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full"></span>
              </button>
              
              {showNotifications && (
                <div className="absolute right-0 top-12 w-80 bg-white rounded-lg shadow-lg border border-gray-200 z-50">
                  <div className="p-3 border-b border-gray-200">
                    <h3 className="font-medium text-gray-900">Notifications</h3>
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    {mockNotifications.map(notif => (
                      <div key={notif.id} className="p-3 border-b border-gray-100 hover:bg-gray-50">
                        <p className="text-sm text-gray-900">{notif.message}</p>
                        <p className="text-xs text-gray-500 mt-1">{notif.time}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
          
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Search properties, tasks, or messages..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Properties List */}
        <div className="flex-1 overflow-y-auto">
          {mockProperties.map(property => (
            <div key={property.id}>
              <div 
                className={`p-4 cursor-pointer border-b border-gray-100 ${
                  selectedProperty.id === property.id ? 'bg-blue-50 border-l-4 border-l-blue-500' : 'hover:bg-gray-50'
                }`}
                onClick={() => {
                  setSelectedProperty(property);
                  setSelectedChannel(property.channels[0]);
                  setSelectedTask(null);
                }}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-medium text-gray-900">{property.name}</h3>
                    <p className="text-sm text-gray-500">{property.unitCount} units</p>
                  </div>
                  <MapPin className="w-4 h-4 text-gray-400" />
                </div>
              </div>
              
              {selectedProperty.id === property.id && (
                <div className="bg-gray-50">
                  {property.channels.map(channel => (
                    <div
                      key={channel.id}
                      className={`px-6 py-3 cursor-pointer border-b border-gray-100 ${
                        selectedChannel.id === channel.id ? 'bg-white border-l-4 border-l-blue-500' : 'hover:bg-white'
                      }`}
                      onClick={() => {
                        setSelectedChannel(channel);
                        setSelectedTask(null);
                      }}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <MessageSquare className="w-4 h-4 text-gray-600" />
                          <span className="text-sm font-medium text-gray-900">{channel.name}</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          {channel.unread > 0 && (
                            <span className="px-2 py-1 text-xs bg-blue-500 text-white rounded-full">
                              {channel.unread}
                            </span>
                          )}
                          <span className="text-xs text-gray-500">{channel.lastActivity}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* User Profile */}
        <div className="p-4 border-t border-gray-200">
          <div className="flex items-center space-x-3">
            <img src={mockUser.avatar} alt={mockUser.name} className="w-8 h-8 rounded-full" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 truncate">{mockUser.name}</p>
              <p className="text-xs text-gray-500">{mockUser.role.replace('_', ' ')}</p>
            </div>
            <Settings className="w-4 h-4 text-gray-400" />
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Channel Header */}
        <div className="bg-white border-b border-gray-200 px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">
                {selectedProperty.name} • {selectedChannel.name}
              </h2>
              <p className="text-sm text-gray-500">{selectedProperty.address}</p>
            </div>
            <div className="flex items-center space-x-3">
              <button className="flex items-center space-x-2 px-3 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700">
                <Plus className="w-4 h-4" />
                <span>New Task</span>
              </button>
              <button className="p-2 rounded-lg hover:bg-gray-100">
                <Upload className="w-4 h-4 text-gray-600" />
              </button>
              <button className="p-2 rounded-lg hover:bg-gray-100">
                <Filter className="w-4 h-4 text-gray-600" />
              </button>
            </div>
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 flex">
          {/* Task List */}
          <div className="w-96 bg-white border-r border-gray-200 overflow-y-auto">
            <div className="p-4 border-b border-gray-200">
              <h3 className="font-medium text-gray-900">Tasks ({channelTasks.length})</h3>
            </div>
            
            <div className="space-y-1">
              {channelTasks.map(task => (
                <div
                  key={task.id}
                  className={`p-4 cursor-pointer border-b border-gray-100 hover:bg-gray-50 ${
                    selectedTask?.id === task.id ? 'bg-blue-50 border-l-4 border-l-blue-500' : ''
                  }`}
                  onClick={() => setSelectedTask(task)}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(task.status)}
                      <span className={`px-2 py-1 text-xs rounded-full border ${getPriorityColor(task.priority)}`}>
                        {task.priority}
                      </span>
                    </div>
                    <MoreVertical className="w-4 h-4 text-gray-400" />
                  </div>
                  
                  <h4 className="font-medium text-gray-900 mb-1">{task.title}</h4>
                  <p className="text-sm text-gray-600 mb-3 line-clamp-2">{task.description}</p>
                  
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <div className="flex items-center space-x-2">
                      <Users className="w-3 h-3" />
                      <span>{task.assignee}</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Calendar className="w-3 h-3" />
                      <span>{new Date(task.dueDate).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Task Detail & Chat */}
          <div className="flex-1 flex flex-col">
            {selectedTask ? (
              <>
                {/* Task Header */}
                <div className="bg-white border-b border-gray-200 p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        {getStatusIcon(selectedTask.status)}
                        <h3 className="text-xl font-semibold text-gray-900">{selectedTask.title}</h3>
                        <span className={`px-3 py-1 text-sm rounded-full border ${getPriorityColor(selectedTask.priority)}`}>
                          {selectedTask.priority} priority
                        </span>
                      </div>
                      <p className="text-gray-600 mb-4">{selectedTask.description}</p>
                      
                      <div className="grid grid-cols-3 gap-4 text-sm">
                        <div>
                          <span className="text-gray-500">Assignee:</span>
                          <p className="font-medium text-gray-900">{selectedTask.assignee}</p>
                        </div>
                        <div>
                          <span className="text-gray-500">Due Date:</span>
                          <p className="font-medium text-gray-900">{new Date(selectedTask.dueDate).toLocaleDateString()}</p>
                        </div>
                        <div>
                          <span className="text-gray-500">Status:</span>
                          <p className="font-medium text-gray-900">{selectedTask.status.replace('_', ' ')}</p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <button className="px-4 py-2 bg-green-600 text-white rounded-lg text-sm hover:bg-green-700">
                        Complete Task
                      </button>
                      <button className="p-2 rounded-lg hover:bg-gray-100">
                        <MoreVertical className="w-4 h-4 text-gray-600" />
                      </button>
                    </div>
                  </div>
                </div>

                {/* Chat Thread */}
                <div className="flex-1 overflow-y-auto p-6">
                  <div className="space-y-4">
                    {selectedTask.messages.map(message => (
                      <div key={message.id} className={`flex ${message.isSystem ? 'justify-center' : 'justify-start'}`}>
                        <div className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                          message.isSystem 
                            ? 'bg-blue-100 text-blue-800 text-sm' 
                            : 'bg-gray-100 text-gray-900'
                        }`}>
                          {!message.isSystem && (
                            <p className="text-xs font-medium text-gray-600 mb-1">{message.author}</p>
                          )}
                          <p className="text-sm">{message.content}</p>
                          <p className="text-xs text-gray-500 mt-1">{message.timestamp}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Message Input */}
                <div className="bg-white border-t border-gray-200 p-4">
                  <div className="flex items-center space-x-3">
                    <button className="p-2 rounded-lg hover:bg-gray-100">
                      <Camera className="w-4 h-4 text-gray-600" />
                    </button>
                    <button className="p-2 rounded-lg hover:bg-gray-100">
                      <Mic className="w-4 h-4 text-gray-600" />
                    </button>
                    <div className="flex-1">
                      <input
                        type="text"
                        placeholder="Type a message..."
                        value={newMessage}
                        onChange={(e) => setNewMessage(e.target.value)}
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        onKeyPress={(e) => {
                          if (e.key === 'Enter' && newMessage.trim()) {
                            // Add message logic here
                            setNewMessage('');
                          }
                        }}
                      />
                    </div>
                    <button 
                      className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                      disabled={!newMessage.trim()}
                    >
                      Send
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-gray-500">
                <div className="text-center">
                  <MessageSquare className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                  <h3 className="text-lg font-medium mb-2">Select a task to view details</h3>
                  <p className="text-gray-400">Choose a task from the list to see its thread and collaborate</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default OverseeNOI;