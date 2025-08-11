// =====================================================
// MANIFEST V3 CONFIGURATION
// =====================================================

// manifest.json
{
  "manifest_version": 3,
  "name": "OverseeNOI Activity Monitor",
  "version": "1.0.0",
  "description": "Workflow efficiency monitoring for property management systems",
  "permissions": [
    "storage",
    "activeTab",
    "scripting"
  ],
  "host_permissions": [
    "https://*.yardi.com/*",
    "https://*.realpage.com/*",
    "https://*.entrata.com/*",
    "https://*.appfolio.com/*",
    "https://api.oversee-noi.com/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": [
        "https://*.yardi.com/*",
        "https://*.realpage.com/*",
        "https://*.entrata.com/*",
        "https://*.appfolio.com/*"
      ],
      "js": ["content.js"],
      "run_at": "document_end"
    }
  ],
  "action": {
    "default_popup": "popup.html",
    "default_title": "OverseeNOI Monitor"
  },
  "icons": {
    "16": "icons/icon16.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  }
}

// =====================================================
// BACKGROUND SERVICE WORKER
// =====================================================

// background.js
class BackgroundService {
  private eventQueue: any[] = [];
  private isOnline = true;
  private syncInterval: NodeJS.Timeout;

  constructor() {
    this.setupEventListeners();
    this.startSyncLoop();
  }

  private setupEventListeners(): void {
    // Handle messages from content scripts
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      switch (request.type) {
        case 'ACTIVITY_EVENT':
          this.handleActivityEvent(request.data, sender.tab?.id);
          break;
        case 'CONSENT_UPDATED':
          this.handleConsentUpdate(request.data);
          break;
        case 'GET_CONFIG':
          this.getConfigForSite(request.url).then(sendResponse);
          return true; // Async response
      }
    });

    // Monitor tab changes for context switching
    chrome.tabs.onActivated.addListener((activeInfo) => {
      this.handleTabSwitch(activeInfo);
    });

    // Handle network status changes
    chrome.runtime.onConnect.addListener((port) => {
      if (port.name === 'keepAlive') {
        this.setupKeepAlive(port);
      }
    });
  }

  private async handleActivityEvent(event: any, tabId: number): Promise<void> {
    // Validate and sanitize event data
    const sanitizedEvent = await this.sanitizeEvent(event);
    
    // Add to queue for batch processing
    this.eventQueue.push({
      ...sanitizedEvent,
      tabId,
      timestamp: Date.now(),
      id: this.generateEventId(),
    });

    // Trigger immediate sync if queue is large
    if (this.eventQueue.length >= 10) {
      this.syncEvents();
    }
  }

  private async sanitizeEvent(event: any): Promise<any> {
    const config = await this.getStoredConfig();
    
    // Only include whitelisted PII fields
    const allowedPiiFields = config.piiWhitelist || [];
    const sanitized = { ...event };

    // Hash sensitive identifiers
    if (sanitized.recordId && !allowedPiiFields.includes('recordId')) {
      sanitized.recordIdHash = await this.hashValue(sanitized.recordId);
      delete sanitized.recordId;
    }

    if (sanitized.userId && !allowedPiiFields.includes('userId')) {
      sanitized.userIdHash = await this.hashValue(sanitized.userId);
      delete sanitized.userId;
    }

    // Remove any PII that's not explicitly whitelisted
    const piiFields = ['tenantName', 'ssn', 'email', 'phone'];
    piiFields.forEach(field => {
      if (sanitized[field] && !allowedPiiFields.includes(field)) {
        delete sanitized[field];
      }
    });

    return sanitized;
  }

  private async syncEvents(): Promise<void> {
    if (this.eventQueue.length === 0 || !this.isOnline) return;

    const config = await this.getStoredConfig();
    if (!config.enabled || !config.accessToken) return;

    try {
      const events = this.eventQueue.splice(0, 50); // Batch size limit
      
      const response = await fetch(`${config.apiUrl}/api/ingest/activity`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.accessToken}`,
          'X-Extension-Version': chrome.runtime.getManifest().version,
        },
        body: JSON.stringify({ events }),
      });

      if (!response.ok) {
        // Re-queue events on failure
        this.eventQueue.unshift(...events);
        throw new Error(`Sync failed: ${response.status}`);
      }

      console.log(`Synced ${events.length} events successfully`);
    } catch (error) {
      console.error('Event sync failed:', error);
      this.isOnline = false;
      setTimeout(() => { this.isOnline = true; }, 30000); // Retry after 30s
    }
  }

  private startSyncLoop(): void {
    this.syncInterval = setInterval(() => {
      this.syncEvents();
    }, 15000); // Sync every 15 seconds
  }

  private async getConfigForSite(url: string): Promise<any> {
    const config = await this.getStoredConfig();
    const siteConfig = config.siteConfigs?.[this.detectPMS(url)];
    
    return {
      enabled: config.enabled && siteConfig?.enabled,
      selectorPack: siteConfig?.selectors,
      piiWhitelist: config.piiWhitelist || [],
      throttleMs: config.throttleMs || 1000,
    };
  }

  private detectPMS(url: string): string {
    if (url.includes('yardi.com')) return 'yardi';
    if (url.includes('realpage.com')) return 'realpage';
    if (url.includes('entrata.com')) return 'entrata';
    if (url.includes('appfolio.com')) return 'appfolio';
    return 'unknown';
  }

  private async getStoredConfig(): Promise<any> {
    const result = await chrome.storage.local.get(['config']);
    return result.config || {};
  }

  private async hashValue(value: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(value + 'oversee-noi-salt');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private generateEventId(): string {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  }

  private handleTabSwitch(activeInfo: any): void {
    // Track context switching behavior
    this.eventQueue.push({
      type: 'TAB_SWITCH',
      tabId: activeInfo.tabId,
      timestamp: Date.now(),
      id: this.generateEventId(),
    });
  }

  private setupKeepAlive(port: any): void {
    port.onDisconnect.addListener(() => {
      // Content script disconnected, clean up if needed
    });
  }
}

// Initialize background service
new BackgroundService();

// =====================================================
// CONTENT SCRIPT
// =====================================================

// content.js
class ActivityMonitor {
  private config: any = {};
  private selectorPack: any = {};
  private lastActivity: number = Date.now();
  private currentSession: any = {};
  private eventThrottle: Map<string, number> = new Map();
  private observer: MutationObserver;
  private port: chrome.runtime.Port;

  constructor() {
    this.init();
  }

  private async init(): Promise<void> {
    // Get configuration for this site
    this.config = await this.getConfig();
    
    if (!this.config.enabled) {
      console.log('OverseeNOI: Monitoring disabled for this site');
      return;
    }

    this.selectorPack = this.config.selectorPack;
    this.setupActivityTracking();
    this.setupDOMObserver();
    this.detectPageContext();
    
    // Keep background connection alive
    this.port = chrome.runtime.connect({ name: 'keepAlive' });
    
    console.log('OverseeNOI: Activity monitoring started');
  }

  private async getConfig(): Promise<any> {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        type: 'GET_CONFIG',
        url: window.location.href,
      }, resolve);
    });
  }

  private setupActivityTracking(): void {
    // Track user interactions
    const events = ['click', 'keydown', 'focus', 'blur'];
    events.forEach(eventType => {
      document.addEventListener(eventType, (e) => {
        this.trackUserInteraction(eventType, e);
      }, { passive: true });
    });

    // Track form submissions
    document.addEventListener('submit', (e) => {
      this.trackFormSubmission(e);
    });

    // Track XHR/Fetch requests
    this.interceptNetworkRequests();
    
    // Track idle time
    this.setupIdleTracking();
  }

  private trackUserInteraction(eventType: string, event: Event): void {
    if (!this.shouldTrackEvent(eventType)) return;

    const element = event.target as HTMLElement;
    const context = this.getElementContext(element);
    
    const activityEvent = {
      type: 'USER_INTERACTION',
      action: eventType,
      context: {
        ...this.getCurrentPageContext(),
        element: context,
        timestamp: Date.now(),
      },
      duration: Date.now() - this.lastActivity,
    };

    this.sendActivityEvent(activityEvent);
    this.lastActivity = Date.now();
  }

  private trackFormSubmission(event: Event): void {
    const form = event.target as HTMLFormElement;
    const formData = new FormData(form);
    
    // Extract non-PII form metadata
    const fields = Array.from(formData.keys()).filter(key => 
      this.config.piiWhitelist.includes(key) || !this.isPiiField(key)
    );

    const activityEvent = {
      type: 'FORM_SUBMISSION',
      action: 'submit',
      context: {
        ...this.getCurrentPageContext(),
        formId: form.id,
        formAction: form.action,
        fieldCount: fields.length,
        fields: fields,
      },
      success: true, // Will be updated if validation fails
    };

    this.sendActivityEvent(activityEvent);
  }

  private interceptNetworkRequests(): void {
    // Intercept XMLHttpRequest
    const originalXHR = window.XMLHttpRequest;
    const self = this;
    
    window.XMLHttpRequest = function() {
      const xhr = new originalXHR();
      const originalSend = xhr.send;
      const originalOpen = xhr.open;
      
      let method: string, url: string;
      
      xhr.open = function(m: string, u: string, ...args: any[]) {
        method = m;
        url = u;
        return originalOpen.apply(this, [m, u, ...args]);
      };
      
      xhr.send = function(data: any) {
        const startTime = Date.now();
        
        xhr.addEventListener('loadend', () => {
          self.trackNetworkRequest(method, url, xhr.status, Date.now() - startTime);
        });
        
        return originalSend.apply(this, [data]);
      };
      
      return xhr;
    };

    // Intercept fetch
    const originalFetch = window.fetch;
    window.fetch = function(...args: any[]) {
      const startTime = Date.now();
      const url = args[0];
      const options = args[1] || {};
      
      return originalFetch.apply(this, args).then(response => {
        self.trackNetworkRequest(
          options.method || 'GET',
          url,
          response.status,
          Date.now() - startTime
        );
        return response;
      });
    };
  }

  private trackNetworkRequest(method: string, url: string, status: number, duration: number): void {
    // Only track relevant PMS API calls
    if (!this.isRelevantPMSRequest(url)) return;

    const activityEvent = {
      type: 'NETWORK_REQUEST',
      action: method.toLowerCase(),
      context: {
        ...this.getCurrentPageContext(),
        url: this.sanitizeUrl(url),
        status,
        duration,
      },
      success: status >= 200 && status < 400,
    };

    this.sendActivityEvent(activityEvent);
  }

  private setupIdleTracking(): void {
    let idleStart: number | null = null;
    
    const resetIdle = () => {
      if (idleStart) {
        const idleDuration = Date.now() - idleStart;
        if (idleDuration > 30000) { // Track idle periods > 30s
          this.sendActivityEvent({
            type: 'IDLE_PERIOD',
            action: 'idle',
            context: this.getCurrentPageContext(),
            duration: idleDuration,
          });
        }
        idleStart = null;
      }
    };

    const startIdle = () => {
      if (!idleStart) {
        idleStart = Date.now();
      }
    };

    ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
      document.addEventListener(event, resetIdle, { passive: true });
    });

    // Start idle timer after 5 seconds of inactivity
    setInterval(() => {
      if (Date.now() - this.lastActivity > 5000) {
        startIdle();
      }
    }, 1000);
  }

  private setupDOMObserver(): void {
    this.observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          // Check for new data tables or forms that might indicate page state changes
          const relevantNodes = Array.from(mutation.addedNodes).filter(node => 
            node.nodeType === Node.ELEMENT_NODE && this.isRelevantElement(node as Element)
          );

          if (relevantNodes.length > 0) {
            this.detectPageContext(); // Re-analyze page context
          }
        }
      });
    });

    this.observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  private detectPageContext(): void {
    const context = this.getCurrentPageContext();
    
    // Only send if context has meaningfully changed
    if (JSON.stringify(context) !== JSON.stringify(this.currentSession.context)) {
      this.currentSession = {
        context,
        startTime: Date.now(),
      };

      this.sendActivityEvent({
        type: 'PAGE_CONTEXT',
        action: 'detected',
        context,
      });
    }
  }

  private getCurrentPageContext(): any {
    const url = window.location.href;
    const pms = this.detectPMS(url);
    
    // Use selector pack to identify current module/context
    const context: any = {
      pms,
      url: this.sanitizeUrl(url),
      title: document.title,
      module: this.detectModule(),
      recordType: this.detectRecordType(),
    };

    // Extract record ID if present and whitelisted
    const recordId = this.extractRecordId();
    if (recordId && this.config.piiWhitelist.includes('recordId')) {
      context.recordId = recordId;
    }

    return context;
  }

  private detectModule(): string {
    const url = window.location.href.toLowerCase();
    const path = window.location.pathname.toLowerCase();
    
    // Common PMS module detection patterns
    if (url.includes('ar') || url.includes('receivab') || path.includes('/ar/')) return 'ar';
    if (url.includes('lease') || path.includes('/lease/')) return 'leasing';
    if (url.includes('maintenance') || url.includes('workorder') || path.includes('/wo/')) return 'maintenance';
    if (url.includes('gl') || url.includes('accounting')) return 'accounting';
    if (url.includes('report')) return 'reporting';
    if (url.includes('resident') || url.includes('tenant')) return 'resident';
    
    // Use selector pack for more specific detection
    if (this.selectorPack?.moduleSelectors) {
      for (const [module, selectors] of Object.entries(this.selectorPack.moduleSelectors)) {
        if (document.querySelector(selectors.identifier)) {
          return module;
        }
      }
    }
    
    return 'unknown';
  }

  private detectRecordType(): string {
    // Look for common record type indicators
    const indicators = {
      unit: ['unit-', '#unit', '.unit', 'unit_id'],
      lease: ['lease-', '#lease', '.lease', 'lease_id'],
      tenant: ['tenant-', '#tenant', '.tenant', 'resident-'],
      workorder: ['wo-', '#wo', '.workorder', 'work_order'],
    };

    for (const [type, selectors] of Object.entries(indicators)) {
      for (const selector of selectors) {
        if (document.querySelector(selector) || 
            document.body.innerHTML.toLowerCase().includes(selector.replace(/[#.]/g, ''))) {
          return type;
        }
      }
    }

    return 'unknown';
  }

  private extractRecordId(): string | null {
    // Extract record ID from URL or page elements
    const urlMatch = window.location.href.match(/(?:id|unit|lease|tenant|wo)=?([a-zA-Z0-9-]+)/i);
    if (urlMatch) return urlMatch[1];

    // Look for ID in common element patterns
    const idSelectors = ['#record-id', '.record-id', '[data-id]', '[data-record-id]'];
    for (const selector of idSelectors) {
      const element = document.querySelector(selector);
      if (element) {
        return element.getAttribute('data-id') || 
               element.getAttribute('data-record-id') || 
               element.textContent?.trim() || null;
      }
    }

    return null;
  }

  private getElementContext(element: HTMLElement): any {
    return {
      tagName: element.tagName.toLowerCase(),
      id: element.id || null,
      className: element.className || null,
      type: element.getAttribute('type') || null,
      name: element.getAttribute('name') || null,
      placeholder: element.getAttribute('placeholder') || null,
      textContent: element.textContent?.substring(0, 50) || null, // Truncated for privacy
    };
  }

  private shouldTrackEvent(eventType: string): boolean {
    const throttleKey = `${eventType}-${Date.now()}`;
    const lastEventTime = this.eventThrottle.get(eventType) || 0;
    
    // Throttle rapid events
    if (Date.now() - lastEventTime < this.config.throttleMs) {
      return false;
    }
    
    this.eventThrottle.set(eventType, Date.now());
    return true;
  }

  private isRelevantPMSRequest(url: string): boolean {
    const patterns = [
      '/api/', '/services/', '/data/', '/ajax/',
      'rentroll', 'lease', 'tenant', 'unit', 'workorder', 'ar'
    ];
    
    return patterns.some(pattern => url.toLowerCase().includes(pattern));
  }

  private isRelevantElement(element: Element): boolean {
    const relevantTags = ['table', 'form', 'iframe'];
    const relevantClasses = ['data-table', 'form-container', 'modal'];
    
    return relevantTags.includes(element.tagName.toLowerCase()) ||
           relevantClasses.some(cls => element.classList.contains(cls));
  }

  private isPiiField(fieldName: string): boolean {
    const piiPatterns = [
      'ssn', 'social', 'tax', 'license', 'phone', 'email', 'address',
      'name', 'first', 'last', 'tenant', 'resident', 'emergency'
    ];
    
    return piiPatterns.some(pattern => 
      fieldName.toLowerCase().includes(pattern)
    );
  }

  private sanitizeUrl(url: string): string {
    try {
      const urlObj = new URL(url);
      // Remove sensitive query parameters
      const sensitiveParams = ['ssn', 'tenant_id', 'resident_id', 'email'];
      sensitiveParams.forEach(param => urlObj.searchParams.delete(param));
      return urlObj.toString();
    } catch {
      return url;
    }
  }

  private detectPMS(url: string): string {
    if (url.includes('yardi.com')) return 'yardi';
    if (url.includes('realpage.com')) return 'realpage';
    if (url.includes('entrata.com')) return 'entrata';
    if (url.includes('appfolio.com')) return 'appfolio';
    return 'unknown';
  }

  private sendActivityEvent(event: any): void {
    chrome.runtime.sendMessage({
      type: 'ACTIVITY_EVENT',
      data: event,
    });
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new ActivityMonitor());
} else {
  new ActivityMonitor();
}

// =====================================================
// POPUP INTERFACE
// =====================================================

// popup.html
`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {
      width: 300px;
      padding: 16px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
    }
    .header {
      display: flex;
      align-items: center;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid #e5e5e5;
    }
    .logo {
      width: 24px;
      height: 24px;
      margin-right: 8px;
      background: #3b82f6;
      border-radius: 4px;
    }
    .status {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }
    .status-dot.active { background: #10b981; }
    .status-dot.inactive { background: #ef4444; }
    .toggle-container {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }
    .toggle {
      position: relative;
      width: 44px;
      height: 24px;
      background: #ccc;
      border-radius: 12px;
      cursor: pointer;
      transition: background 0.3s;
    }
    .toggle.active { background: #3b82f6; }
    .toggle-knob {
      position: absolute;
      top: 2px;
      left: 2px;
      width: 20px;
      height: 20px;
      background: white;
      border-radius: 50%;
      transition: transform 0.3s;
    }
    .toggle.active .toggle-knob { transform: translateX(20px); }
    .stats {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 16px;
    }
    .stat {
      text-align: center;
      padding: 8px;
      background: #f9fafb;
      border-radius: 6px;
    }
    .stat-value {
      font-size: 18px;
      font-weight: 600;
      color: #1f2937;
    }
    .stat-label {
      font-size: 12px;
      color: #6b7280;
      margin-top: 4px;
    }
    .actions {
      display: flex;
      gap: 8px;
    }
    .btn {
      flex: 1;
      padding: 8px 12px;
      border: 1px solid #d1d5db;
      background: white;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      text-align: center;
    }
    .btn:hover { background: #f9fafb; }
    .btn.primary {
      background: #3b82f6;
      color: white;
      border-color: #3b82f6;
    }
    .btn.primary:hover { background: #2563eb; }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo"></div>
    <div>
      <div style="font-weight: 600;">OverseeNOI Monitor</div>
      <div style="font-size: 12px; color: #6b7280;">Activity Tracking</div>
    </div>
  </div>

  <div class="status">
    <div class="status-dot" id="statusDot"></div>
    <span id="statusText">Checking status...</span>
  </div>

  <div class="toggle-container">
    <span>Enable Monitoring</span>
    <div class="toggle" id="monitorToggle">
      <div class="toggle-knob"></div>
    </div>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-value" id="eventsToday">-</div>
      <div class="stat-label">Events Today</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="avgResponse">-</div>
      <div class="stat-label">Avg Response</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="efficiency">-</div>
      <div class="stat-label">Efficiency</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="queueSize">-</div>
      <div class="stat-label">Queue Size</div>
    </div>
  </div>

  <div class="actions">
    <button class="btn" id="settingsBtn">Settings</button>
    <button class="btn primary" id="dashboardBtn">Dashboard</button>
  </div>

  <script src="popup.js"></script>
</body>
</html>`

// popup.js
class PopupController {
  private config: any = {};

  constructor() {
    this.init();
  }

  private async init(): Promise<void> {
    await this.loadConfig();
    this.setupEventListeners();
    this.updateUI();
    this.loadStats();
  }

  private async loadConfig(): Promise<void> {
    const result = await chrome.storage.local.get(['config']);
    this.config = result.config || { enabled: false };
  }

  private setupEventListeners(): void {
    const toggle = document.getElementById('monitorToggle') as HTMLElement;
    const settingsBtn = document.getElementById('settingsBtn') as HTMLElement;
    const dashboardBtn = document.getElementById('dashboardBtn') as HTMLElement;

    toggle.addEventListener('click', () => this.toggleMonitoring());
    settingsBtn.addEventListener('click', () => this.openSettings());
    dashboardBtn.addEventListener('click', () => this.openDashboard());
  }

  private async toggleMonitoring(): Promise<void> {
    this.config.enabled = !this.config.enabled;
    await chrome.storage.local.set({ config: this.config });
    this.updateUI();
    
    // Notify all tabs of the change
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    tabs.forEach(tab => {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'CONFIG_UPDATED',
          config: this.config,
        });
      }
    });
  }

  private updateUI(): void {
    const statusDot = document.getElementById('statusDot') as HTMLElement;
    const statusText = document.getElementById('statusText') as HTMLElement;
    const toggle = document.getElementById('monitorToggle') as HTMLElement;

    if (this.config.enabled) {
      statusDot.className = 'status-dot active';
      statusText.textContent = 'Monitoring Active';
      toggle.classList.add('active');
    } else {
      statusDot.className = 'status-dot inactive';
      statusText.textContent = 'Monitoring Disabled';
      toggle.classList.remove('active');
    }
  }

  private async loadStats(): Promise<void> {
    try {
      // Get stats from storage or API
      const stats = await this.getStoredStats();
      
      document.getElementById('eventsToday')!.textContent = stats.eventsToday || '0';
      document.getElementById('avgResponse')!.textContent = stats.avgResponse || '-';
      document.getElementById('efficiency')!.textContent = stats.efficiency || '-';
      document.getElementById('queueSize')!.textContent = stats.queueSize || '0';
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }

  private async getStoredStats(): Promise<any> {
    const result = await chrome.storage.local.get(['stats']);
    return result.stats || {};
  }

  private openSettings(): void {
    chrome.tabs.create({
      url: chrome.runtime.getURL('settings.html'),
    });
  }

  private openDashboard(): void {
    const dashboardUrl = this.config.dashboardUrl || 'https://app.oversee-noi.com/dashboard';
    chrome.tabs.create({ url: dashboardUrl });
  }
}

// Initialize popup
new PopupController();

// =====================================================
// SELECTOR PACK DEFINITIONS
// =====================================================

// configs/yardi-selectors.json
{
  "pms": "yardi",
  "moduleSelectors": {
    "ar": {
      "identifier": "#ARMain, .ar-module",
      "table": "#DataGrid1, .ar-grid",
      "balanceColumn": "td:contains('Balance')",
      "tenantColumn": "td:contains('Tenant')",
      "unitColumn": "td:contains('Unit')"
    },
    "leasing": {
      "identifier": "#LeasingMain, .leasing-module",
      "availableUnits": ".available-units-grid",
      "rentColumn": "td:contains('Rent')",
      "statusColumn": "td:contains('Status')"
    },
    "maintenance": {
      "identifier": "#MaintenanceMain, .wo-module",
      "workOrderGrid": ".work-order-grid",
      "statusColumn": "td:contains('WO Status')",
      "priorityColumn": "td:contains('Priority')"
    }
  },
  "xhrPatterns": [
    {
      "urlSubstring": "/GetRentRoll",
      "responseMap": "rentRollResponse"
    },
    {
      "urlSubstring": "/GetAvailableUnits",
      "responseMap": "availableUnitsResponse"
    }
  ],
  "formSelectors": {
    "leaseForm": "#LeaseForm",
    "paymentForm": "#PaymentForm",
    "workOrderForm": "#WorkOrderForm"
  }
}

// configs/realpage-selectors.json
{
  "pms": "realpage",
  "moduleSelectors": {
    "ar": {
      "identifier": ".rp-ar-module",
      "table": ".rp-data-grid",
      "balanceColumn": ".balance-cell",
      "residentColumn": ".resident-cell"
    },
    "leasing": {
      "identifier": ".rp-leasing-module",
      "unitGrid": ".unit-grid",
      "rentColumn": ".rent-cell",
      "availabilityColumn": ".availability-cell"
    }
  },
  "xhrPatterns": [
    {
      "urlSubstring": "/api/residents",
      "responseMap": "residentsResponse"
    },
    {
      "urlSubstring": "/api/units",
      "responseMap": "unitsResponse"
    }
  ]
}