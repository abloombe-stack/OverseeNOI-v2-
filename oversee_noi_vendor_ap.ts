// =====================================================
// VENDOR MANAGEMENT SYSTEM
// =====================================================

// src/vendor/vendor.service.ts
import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { TasksService } from '../tasks/tasks.service';
import { NotificationService } from '../notification/notification.service';
import { FilesService } from '../files/files.service';

interface BidRequest {
  taskId: string;
  title: string;
  description: string;
  scope: string;
  requirements: string[];
  dueDate: Date;
  budget?: number;
  propertyId: string;
  categoryId: string;
  attachments?: string[];
}

interface BidSubmission {
  bidRequestId: string;
  vendorId: string;
  amount: number;
  timeline: string;
  proposal: string;
  attachments: string[];
  warranty?: string;
  insurance?: {
    liability: number;
    workersComp: boolean;
    bondRequired: boolean;
  };
}

@Injectable()
export class VendorService {
  private readonly logger = new Logger(VendorService.name);

  constructor(
    private prisma: PrismaService,
    private tasksService: TasksService,
    private notificationService: NotificationService,
    private filesService: FilesService,
  ) {}

  async createBidRequest(request: BidRequest, userId: string): Promise<any> {
    // Validate user permissions
    await this.validateTaskAccess(request.taskId, userId);

    // Create bid request
    const bidRequest = await this.prisma.bidRequest.create({
      data: {
        taskId: request.taskId,
        title: request.title,
        description: request.description,
        scope: request.scope,
        requirements: request.requirements,
        dueDate: request.dueDate,
        budget: request.budget,
        propertyId: request.propertyId,
        categoryId: request.categoryId,
        status: 'OPEN',
        createdById: userId,
        attachments: request.attachments || [],
      },
    });

    // Find qualified vendors for this category and property
    const qualifiedVendors = await this.findQualifiedVendors(
      request.categoryId,
      request.propertyId,
      request.budget,
    );

    // Send invitations to qualified vendors
    await this.sendBidInvitations(bidRequest.id, qualifiedVendors);

    // Create vendor access channel
    await this.createVendorChannel(bidRequest.id, qualifiedVendors);

    return bidRequest;
  }

  async submitBid(submission: BidSubmission): Promise<any> {
    const bidRequest = await this.prisma.bidRequest.findUnique({
      where: { id: submission.bidRequestId },
      include: { task: true, property: true },
    });

    if (!bidRequest) {
      throw new BadRequestException('Bid request not found');
    }

    if (bidRequest.status !== 'OPEN') {
      throw new BadRequestException('Bid request is no longer accepting submissions');
    }

    if (new Date() > bidRequest.dueDate) {
      throw new BadRequestException('Bid submission deadline has passed');
    }

    // Validate vendor eligibility
    await this.validateVendorEligibility(submission.vendorId, bidRequest.propertyId);

    // Create bid submission
    const bid = await this.prisma.bid.create({
      data: {
        bidRequestId: submission.bidRequestId,
        vendorId: submission.vendorId,
        amount: submission.amount,
        timeline: submission.timeline,
        proposal: submission.proposal,
        attachments: submission.attachments,
        warranty: submission.warranty,
        insurance: submission.insurance || {},
        status: 'SUBMITTED',
        submittedAt: new Date(),
      },
    });

    // Notify property management team
    await this.notificationService.send({
      userId: bidRequest.createdById,
      type: 'BID_SUBMITTED',
      title: 'New Bid Received',
      message: `New bid submitted for "${bidRequest.title}" - $${submission.amount}`,
      data: { bidId: bid.id, bidRequestId: submission.bidRequestId },
    });

    // Post to vendor channel
    await this.postBidNotification(bidRequest.id, bid);

    return bid;
  }

  async evaluateBids(bidRequestId: string, userId: string): Promise<any> {
    const bidRequest = await this.prisma.bidRequest.findUnique({
      where: { id: bidRequestId },
      include: {
        bids: {
          include: { vendor: true },
          where: { status: 'SUBMITTED' },
        },
        task: true,
      },
    });

    if (!bidRequest) {
      throw new BadRequestException('Bid request not found');
    }

    await this.validateTaskAccess(bidRequest.taskId, userId);

    // Create bid comparison sheet
    const comparison = await this.createBidComparison(bidRequest.bids);

    // Generate AI evaluation
    const aiAnalysis = await this.generateAIBidAnalysis(bidRequest, bidRequest.bids);

    // Create evaluation task
    const evaluationTask = await this.tasksService.create({
      title: `Evaluate bids for: ${bidRequest.title}`,
      description: `${bidRequest.bids.length} bids received. Review and select winning vendor.`,
      channelId: await this.getChannelForProperty(bidRequest.propertyId, 'capex'),
      priority: 'HIGH',
      tags: ['bid-evaluation', 'vendor-selection'],
      metadata: {
        bidRequestId,
        comparison,
        aiAnalysis,
      },
    }, { id: userId });

    return {
      evaluationTask,
      comparison,
      aiAnalysis,
    };
  }

  async awardBid(bidId: string, userId: string): Promise<any> {
    const bid = await this.prisma.bid.findUnique({
      where: { id: bidId },
      include: {
        vendor: true,
        bidRequest: { include: { task: true } },
      },
    });

    if (!bid) {
      throw new BadRequestException('Bid not found');
    }

    await this.validateTaskAccess(bid.bidRequest.taskId, userId);

    // Update bid status
    await this.prisma.bid.update({
      where: { id: bidId },
      data: { 
        status: 'AWARDED',
        awardedAt: new Date(),
        awardedById: userId,
      },
    });

    // Update other bids to rejected
    await this.prisma.bid.updateMany({
      where: {
        bidRequestId: bid.bidRequestId,
        id: { not: bidId },
      },
      data: { status: 'REJECTED' },
    });

    // Close bid request
    await this.prisma.bidRequest.update({
      where: { id: bid.bidRequestId },
      data: { status: 'AWARDED' },
    });

    // Create work order/contract
    const workOrder = await this.createWorkOrder(bid, userId);

    // Notify vendor
    await this.notificationService.send({
      userId: bid.vendor.userId,
      type: 'BID_AWARDED',
      title: 'Bid Awarded!',
      message: `Congratulations! Your bid for "${bid.bidRequest.title}" has been awarded.`,
      data: { bidId, workOrderId: workOrder.id },
    });

    // Notify rejected vendors
    const rejectedBids = await this.prisma.bid.findMany({
      where: {
        bidRequestId: bid.bidRequestId,
        status: 'REJECTED',
      },
      include: { vendor: true },
    });

    for (const rejectedBid of rejectedBids) {
      await this.notificationService.send({
        userId: rejectedBid.vendor.userId,
        type: 'BID_REJECTED',
        title: 'Bid Not Selected',
        message: `Thank you for your proposal for "${bid.bidRequest.title}". We have selected another vendor for this project.`,
        data: { bidId: rejectedBid.id },
      });
    }

    return workOrder;
  }

  private async findQualifiedVendors(
    categoryId: string,
    propertyId: string,
    budget?: number,
  ): Promise<any[]> {
    const vendors = await this.prisma.vendor.findMany({
      where: {
        active: true,
        categories: {
          has: categoryId,
        },
        serviceAreas: {
          has: propertyId,
        },
        ...(budget && {
          maxProjectSize: { gte: budget },
        }),
      },
      include: {
        user: true,
        certifications: true,
        reviews: {
          orderBy: { createdAt: 'desc' },
          take: 5,
        },
      },
    });

    // Filter by additional criteria
    return vendors.filter(vendor => {
      // Check insurance requirements
      const hasRequiredInsurance = vendor.insurance?.liability >= 1000000;
      
      // Check rating threshold
      const avgRating = vendor.reviews.reduce((sum, r) => sum + r.rating, 0) / vendor.reviews.length;
      const meetsRatingThreshold = vendor.reviews.length === 0 || avgRating >= 3.5;
      
      return hasRequiredInsurance && meetsRatingThreshold;
    });
  }

  private async sendBidInvitations(bidRequestId: string, vendors: any[]): Promise<void> {
    const invitationPromises = vendors.map(vendor =>
      this.notificationService.send({
        userId: vendor.user.id,
        type: 'BID_INVITATION',
        title: 'New Bid Opportunity',
        message: 'You have been invited to submit a bid for a new project.',
        data: { bidRequestId },
        channels: ['push', 'email'],
      })
    );

    await Promise.all(invitationPromises);
  }

  private async createVendorChannel(bidRequestId: string, vendors: any[]): Promise<void> {
    const bidRequest = await this.prisma.bidRequest.findUnique({
      where: { id: bidRequestId },
    });

    const channel = await this.prisma.channel.create({
      data: {
        key: `bid-${bidRequestId}`,
        name: `Bid: ${bidRequest.title}`,
        propertyId: bidRequest.propertyId,
        visibilityRoles: ['VENDOR'],
        metadata: {
          type: 'BID_CHANNEL',
          bidRequestId,
          vendorIds: vendors.map(v => v.id),
        },
      },
    });

    // Add welcome message
    await this.prisma.message.create({
      data: {
        content: `Welcome to the bid channel for "${bidRequest.title}". Please use this channel for questions and clarifications. Bid submissions should be made through the bid portal.`,
        channelId: channel.id,
        authorId: 'system',
        isSystem: true,
      },
    });
  }

  private async createBidComparison(bids: any[]): Promise<any> {
    return {
      summary: {
        totalBids: bids.length,
        priceRange: {
          min: Math.min(...bids.map(b => b.amount)),
          max: Math.max(...bids.map(b => b.amount)),
          avg: bids.reduce((sum, b) => sum + b.amount, 0) / bids.length,
        },
        timelineRange: {
          shortest: Math.min(...bids.map(b => this.parseTimeline(b.timeline))),
          longest: Math.max(...bids.map(b => this.parseTimeline(b.timeline))),
        },
      },
      bids: bids.map(bid => ({
        id: bid.id,
        vendor: bid.vendor.name,
        amount: bid.amount,
        timeline: bid.timeline,
        warranty: bid.warranty,
        hasInsurance: !!bid.insurance?.liability,
        score: this.calculateBidScore(bid),
      })).sort((a, b) => b.score - a.score),
    };
  }

  private async generateAIBidAnalysis(bidRequest: any, bids: any[]): Promise<any> {
    // This would integrate with the AI service
    return {
      recommendation: bids.length > 0 ? bids[0].id : null,
      reasoning: [
        'Vendor has excellent track record with similar projects',
        'Competitive pricing within budget range',
        'Reasonable timeline that meets project requirements',
        'Proper insurance coverage and certifications',
      ],
      risks: [
        'Timeline may be optimistic for project scope',
        'Vendor has limited availability in Q4',
      ],
      alternatives: bids.slice(1, 3).map(bid => ({
        vendorId: bid.vendorId,
        reason: 'Strong alternative with slightly higher cost but faster timeline',
      })),
    };
  }

  private async createWorkOrder(bid: any, userId: string): Promise<any> {
    return await this.prisma.workOrder.create({
      data: {
        bidId: bid.id,
        vendorId: bid.vendorId,
        propertyId: bid.bidRequest.propertyId,
        title: bid.bidRequest.title,
        description: bid.bidRequest.description,
        scope: bid.bidRequest.scope,
        amount: bid.amount,
        timeline: bid.timeline,
        status: 'PENDING_CONTRACT',
        createdById: userId,
        milestones: this.generateMilestones(bid.timeline, bid.amount),
      },
    });
  }

  private parseTimeline(timeline: string): number {
    // Parse timeline strings like "2 weeks", "1 month", etc.
    const match = timeline.match(/(\d+)\s*(day|week|month)s?/i);
    if (!match) return 30; // Default 30 days
    
    const [, num, unit] = match;
    const multiplier = { day: 1, week: 7, month: 30 }[unit.toLowerCase()] || 30;
    return parseInt(num) * multiplier;
  }

  private calculateBidScore(bid: any): number {
    let score = 50; // Base score
    
    // Price competitiveness (lower is better)
    score += (100000 - bid.amount) / 1000; // Rough scoring
    
    // Vendor rating
    const avgRating = bid.vendor.reviews?.length > 0 
      ? bid.vendor.reviews.reduce((sum, r) => sum + r.rating, 0) / bid.vendor.reviews.length
      : 3;
    score += avgRating * 10;
    
    // Insurance coverage
    if (bid.insurance?.liability >= 1000000) score += 10;
    
    // Timeline (shorter reasonable timeline is better)
    const timelineDays = this.parseTimeline(bid.timeline);
    if (timelineDays <= 30) score += 10;
    
    return score;
  }

  private generateMilestones(timeline: string, amount: number): any[] {
    const days = this.parseTimeline(timeline);
    const milestones = [];
    
    // Standard milestone structure
    milestones.push({
      name: 'Project Start',
      percentage: 0,
      amount: 0,
      dueDate: new Date(),
      status: 'PENDING',
    });
    
    if (days > 7) {
      milestones.push({
        name: 'Materials Delivery',
        percentage: 25,
        amount: amount * 0.25,
        dueDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
        status: 'PENDING',
      });
    }
    
    milestones.push({
      name: 'Work Completion',
      percentage: 90,
      amount: amount * 0.9,
      dueDate: new Date(Date.now() + (days - 1) * 24 * 60 * 60 * 1000),
      status: 'PENDING',
    });
    
    milestones.push({
      name: 'Final Inspection',
      percentage: 100,
      amount: amount,
      dueDate: new Date(Date.now() + days * 24 * 60 * 60 * 1000),
      status: 'PENDING',
    });
    
    return milestones;
  }

  private async validateTaskAccess(taskId: string, userId: string): Promise<void> {
    // Implementation would check RBAC permissions
  }

  private async validateVendorEligibility(vendorId: string, propertyId: string): Promise<void> {
    const vendor = await this.prisma.vendor.findUnique({
      where: { id: vendorId },
    });

    if (!vendor.active) {
      throw new BadRequestException('Vendor account is inactive');
    }

    if (!vendor.serviceAreas.includes(propertyId)) {
      throw new BadRequestException('Vendor not qualified for this property');
    }
  }

  private async getChannelForProperty(propertyId: string, channelKey: string): Promise<string> {
    const channel = await this.prisma.channel.findFirst({
      where: { propertyId, key: channelKey },
    });
    return channel?.id;
  }

  private async postBidNotification(bidRequestId: string, bid: any): Promise<void> {
    const channel = await this.prisma.channel.findFirst({
      where: { 
        metadata: { path: ['bidRequestId'], equals: bidRequestId },
      },
    });

    if (channel) {
      await this.prisma.message.create({
        data: {
          content: `New bid submitted: $${bid.amount.toLocaleString()} - ${bid.timeline}`,
          channelId: channel.id,
          authorId: 'system',
          isSystem: true,
        },
      });
    }
  }
}

// =====================================================
// AP AUTOMATION SERVICE
// =====================================================

// src/ap/ap.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { TasksService } from '../tasks/tasks.service';
import { AIService } from '../ai/ai.service';
import * as Tesseract from 'tesseract.js';

interface InvoiceData {
  vendorName: string;
  invoiceNumber: string;
  invoiceDate: Date;
  dueDate: Date;
  amount: number;
  lineItems: LineItem[];
  taxAmount?: number;
  glCodes?: string[];
}

interface LineItem {
  description: string;
  quantity: number;
  unitPrice: number;
  total: number;
  glCode?: string;
}

interface ApprovalWorkflow {
  propertyId: string;
  amount: number;
  category: string;
  approvers: ApprovalLevel[];
}

interface ApprovalLevel {
  level: number;
  role: string;
  threshold: number;
  required: boolean;
}

@Injectable()
export class APService {
  private readonly logger = new Logger(APService.name);

  constructor(
    private prisma: PrismaService,
    private tasksService: TasksService,
    private aiService: AIService,
  ) {}

  async processInvoice(fileBuffer: Buffer, fileName: string, userId: string): Promise<any> {
    try {
      // OCR extraction
      const ocrText = await this.extractTextFromImage(fileBuffer);
      
      // AI-powered data extraction
      const extractedData = await this.extractInvoiceData(ocrText);
      
      // Validate extracted data
      const validationResult = await this.validateInvoiceData(extractedData);
      
      // Create invoice record
      const invoice = await this.prisma.invoice.create({
        data: {
          ...extractedData,
          fileName,
          ocrText,
          extractedData,
          validationResult,
          status: validationResult.isValid ? 'PENDING_CODING' : 'NEEDS_REVIEW',
          uploadedById: userId,
          processedAt: new Date(),
        },
      });

      // Auto-suggest GL codes
      const glSuggestions = await this.suggestGLCodes(extractedData);
      
      if (validationResult.isValid && glSuggestions.confidence > 0.8) {
        // Auto-apply GL codes with high confidence
        await this.applyGLCodes(invoice.id, glSuggestions.codes);
        
        // Start approval workflow
        await this.initiateApprovalWorkflow(invoice.id);
      } else {
        // Create coding task for manual review
        await this.createCodingTask(invoice.id, glSuggestions);
      }

      return {
        invoice,
        validationResult,
        glSuggestions,
        nextAction: validationResult.isValid ? 'APPROVAL' : 'REVIEW',
      };
    } catch (error) {
      this.logger.error('Invoice processing failed:', error);
      throw error;
    }
  }

  async approveInvoice(invoiceId: string, approverId: string, notes?: string): Promise<any> {
    const invoice = await this.prisma.invoice.findUnique({
      where: { id: invoiceId },
      include: { approvals: true, property: true },
    });

    if (!invoice) {
      throw new Error('Invoice not found');
    }

    // Check if user is authorized to approve at current level
    const workflow = await this.getApprovalWorkflow(invoice.propertyId, invoice.amount);
    const currentLevel = this.getCurrentApprovalLevel(invoice, workflow);
    
    if (!await this.canApproveAtLevel(approverId, currentLevel, invoice.propertyId)) {
      throw new Error('Insufficient approval authority');
    }

    // Record approval
    await this.prisma.invoiceApproval.create({
      data: {
        invoiceId,
        approverId,
        level: currentLevel.level,
        notes,
        approvedAt: new Date(),
      },
    });

    // Check if all required approvals are complete
    const isFullyApproved = await this.checkApprovalCompletion(invoiceId, workflow);
    
    if (isFullyApproved) {
      // Mark as approved and queue for payment
      await this.prisma.invoice.update({
        where: { id: invoiceId },
        data: {
          status: 'APPROVED',
          approvedAt: new Date(),
        },
      });

      // Export to accounting system
      await this.exportToAccounting(invoice);
      
      // Create payment task if needed
      await this.createPaymentTask(invoiceId);
    } else {
      // Move to next approval level
      await this.progressToNextApprovalLevel(invoiceId);
    }

    return { isFullyApproved, nextLevel: currentLevel.level + 1 };
  }

  async rejectInvoice(invoiceId: string, rejectorId: string, reason: string): Promise<void> {
    await this.prisma.invoice.update({
      where: { id: invoiceId },
      data: {
        status: 'REJECTED',
        rejectedAt: new Date(),
        rejectionReason: reason,
      },
    });

    await this.prisma.invoiceApproval.create({
      data: {
        invoiceId,
        approverId: rejectorId,
        level: -1, // Rejection level
        notes: reason,
        approvedAt: new Date(),
        isRejection: true,
      },
    });

    // Notify requester and previous approvers
    await this.notifyInvoiceRejection(invoiceId, reason);
  }

  private async extractTextFromImage(buffer: Buffer): Promise<string> {
    const { data: { text } } = await Tesseract.recognize(buffer, 'eng', {
      logger: m => this.logger.debug(m),
    });
    return text;
  }

  private async extractInvoiceData(ocrText: string): Promise<InvoiceData> {
    // Use AI service to extract structured data from OCR text
    const prompt = `
      Extract invoice data from this OCR text:
      ${ocrText}
      
      Return structured JSON with: vendorName, invoiceNumber, invoiceDate, dueDate, amount, lineItems, taxAmount
    `;

    // This would call the AI service to extract structured data
    // For now, simplified extraction logic
    const lines = ocrText.split('\n').filter(line => line.trim());
    
    const extractedData: Partial<InvoiceData> = {
      lineItems: [],
    };

    // Basic pattern matching for common invoice fields
    for (const line of lines) {
      // Vendor name (often at the top)
      if (line.match(/^[A-Z\s&]+$/)) {
        extractedData.vendorName = extractedData.vendorName || line.trim();
      }
      
      // Invoice number
      const invoiceMatch = line.match(/invoice\s*#?\s*:?\s*(\S+)/i);
      if (invoiceMatch) {
        extractedData.invoiceNumber = invoiceMatch[1];
      }
      
      // Date patterns
      const dateMatch = line.match(/(\d{1,2}\/\d{1,2}\/\d{4})/);
      if (dateMatch && !extractedData.invoiceDate) {
        extractedData.invoiceDate = new Date(dateMatch[1]);
      }
      
      // Amount patterns
      const amountMatch = line.match(/\$?([\d,]+\.?\d*)/);
      if (amountMatch && !extractedData.amount) {
        extractedData.amount = parseFloat(amountMatch[1].replace(/,/g, ''));
      }
    }

    return extractedData as InvoiceData;
  }

  private async validateInvoiceData(data: InvoiceData): Promise<any> {
    const errors = [];
    const warnings = [];

    // Required field validation
    if (!data.vendorName) errors.push('Vendor name is required');
    if (!data.invoiceNumber) errors.push('Invoice number is required');
    if (!data.amount || data.amount <= 0) errors.push('Valid amount is required');
    if (!data.invoiceDate) errors.push('Invoice date is required');

    // Business rule validation
    if (data.invoiceDate && data.invoiceDate > new Date()) {
      warnings.push('Invoice date is in the future');
    }

    if (data.dueDate && data.dueDate < new Date()) {
      warnings.push('Invoice is past due');
    }

    // Duplicate check
    const existingInvoice = await this.prisma.invoice.findFirst({
      where: {
        vendorName: data.vendorName,
        invoiceNumber: data.invoiceNumber,
      },
    });

    if (existingInvoice) {
      errors.push('Duplicate invoice detected');
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      confidence: this.calculateExtractionConfidence(data),
    };
  }

  private async suggestGLCodes(data: InvoiceData): Promise<any> {
    // AI-powered GL code suggestion based on vendor, description, and historical data
    const historicalCoding = await this.prisma.invoice.findMany({
      where: { vendorName: data.vendorName },
      select: { glCodes: true, lineItems: true },
      take: 10,
      orderBy: { createdAt: 'desc' },
    });

    // Analyze patterns and suggest codes
    const suggestions = {
      codes: [],
      confidence: 0,
      reasoning: [],
    };

    // Simplified logic - in production, this would use ML
    if (data.vendorName?.toLowerCase().includes('maintenance')) {
      suggestions.codes = ['6200-000']; // Maintenance expense
      suggestions.confidence = 0.85;
      suggestions.reasoning.push('Vendor name indicates maintenance work');
    } else if (data.vendorName?.toLowerCase().includes('utility')) {
      suggestions.codes = ['6100-000']; // Utilities
      suggestions.confidence = 0.9;
      suggestions.reasoning.push('Vendor name indicates utility service');
    }

    return suggestions;
  }

  private async applyGLCodes(invoiceId: string, glCodes: string[]): Promise<void> {
    await this.prisma.invoice.update({
      where: { id: invoiceId },
      data: {
        glCodes,
        status: 'PENDING_APPROVAL',
      },
    });
  }

  private async initiateApprovalWorkflow(invoiceId: string): Promise<void> {
    const invoice = await this.prisma.invoice.findUnique({
      where: { id: invoiceId },
    });

    const workflow = await this.getApprovalWorkflow(
      invoice.propertyId,
      invoice.amount,
    );

    // Create approval task for first level
    const firstLevel = workflow.approvers[0];
    await this.createApprovalTask(invoiceId, firstLevel);
  }

  private async createCodingTask(invoiceId: string, glSuggestions: any): Promise<void> {
    const invoice = await this.prisma.invoice.findUnique({
      where: { id: invoiceId },
      include: { property: true },
    });

    const channel = await this.prisma.channel.findFirst({
      where: {
        propertyId: invoice.propertyId,
        key: 'accounting',
      },
    });

    await this.tasksService.create({
      title: `Code invoice: ${invoice.vendorName} - ${invoice.invoiceNumber}`,
      description: `Review and assign GL codes for invoice. Amount: $${invoice.amount}. AI suggestions: ${glSuggestions.codes.join(', ')} (${glSuggestions.confidence * 100}% confidence)`,
      channelId: channel?.id,
      priority: 'MEDIUM',
      tags: ['ap-automation', 'gl-coding'],
      metadata: {
        invoiceId,
        glSuggestions,
        type: 'GL_CODING',
      },
    }, { id: 'system' });
  }

  private async createApprovalTask(invoiceId: string, approvalLevel: ApprovalLevel): Promise<void> {
    const invoice = await this.prisma.invoice.findUnique({
      where: { id: invoiceId },
      include: { property: true },
    });

    // Find users with the required role for this property
    const approvers = await this.prisma.user.findMany({
      where: {
        roles: {
          some: {
            role: approvalLevel.role,
            OR: [
              { propertyId: invoice.propertyId },
              { propertyId: null }, // Company-wide roles
            ],
          },
        },
      },
    });

    if (approvers.length === 0) {
      throw new Error(`No approvers found for role: ${approvalLevel.role}`);
    }

    // Create approval task
    const channel = await this.prisma.channel.findFirst({
      where: {
        propertyId: invoice.propertyId,
        key: 'accounting',
      },
    });

    await this.tasksService.create({
      title: `Approve invoice: ${invoice.vendorName} - $${invoice.amount}`,
      description: `Invoice requires Level ${approvalLevel.level} approval. Due: ${invoice.dueDate}`,
      channelId: channel?.id,
      assigneeId: approvers[0].id, // Assign to first available approver
      priority: invoice.amount > 10000 ? 'HIGH' : 'MEDIUM',
      tags: ['ap-automation', 'approval-required'],
      metadata: {
        invoiceId,
        approvalLevel: approvalLevel.level,
        type: 'INVOICE_APPROVAL',
      },
    }, { id: 'system' });
  }

  private async getApprovalWorkflow(propertyId: string, amount: number): Promise<ApprovalWorkflow> {
    // Get company-specific approval workflow
    const property = await this.prisma.property.findUnique({
      where: { id: propertyId },
      include: { portfolio: { include: { company: true } } },
    });

    const companySettings = property.portfolio.company.settings as any;
    const approvalRules = companySettings?.approvalWorkflows || this.getDefaultApprovalWorkflow();

    // Find applicable workflow based on amount
    for (const workflow of approvalRules) {
      if (amount <= workflow.maxAmount) {
        return {
          propertyId,
          amount,
          category: 'GENERAL',
          approvers: workflow.levels,
        };
      }
    }

    // Default to highest level workflow
    return approvalRules[approvalRules.length - 1];
  }

  private getDefaultApprovalWorkflow(): any[] {
    return [
      {
        maxAmount: 1000,
        levels: [
          { level: 1, role: 'PROPERTY_MANAGER', threshold: 1000, required: true },
        ],
      },
      {
        maxAmount: 5000,
        levels: [
          { level: 1, role: 'PROPERTY_MANAGER', threshold: 5000, required: true },
          { level: 2, role: 'REGIONAL_PM', threshold: 5000, required: true },
        ],
      },
      {
        maxAmount: 25000,
        levels: [
          { level: 1, role: 'PROPERTY_MANAGER', threshold: 25000, required: true },
          { level: 2, role: 'REGIONAL_PM', threshold: 25000, required: true },
          { level: 3, role: 'ASSET_MANAGER', threshold: 25000, required: true },
        ],
      },
      {
        maxAmount: Infinity,
        levels: [
          { level: 1, role: 'PROPERTY_MANAGER', threshold: Infinity, required: true },
          { level: 2, role: 'REGIONAL_PM', threshold: Infinity, required: true },
          { level: 3, role: 'ASSET_MANAGER', threshold: Infinity, required: true },
          { level: 4, role: 'VP', threshold: Infinity, required: true },
        ],
      },
    ];
  }

  private getCurrentApprovalLevel(invoice: any, workflow: ApprovalWorkflow): ApprovalLevel {
    const completedLevels = invoice.approvals?.map(a => a.level) || [];
    const nextLevel = workflow.approvers.find(level => 
      !completedLevels.includes(level.level)
    );
    return nextLevel || workflow.approvers[0];
  }

  private async canApproveAtLevel(userId: string, level: ApprovalLevel, propertyId: string): Promise<boolean> {
    const userRole = await this.prisma.userRole.findFirst({
      where: {
        userId,
        role: level.role,
        OR: [
          { propertyId },
          { propertyId: null },
        ],
      },
    });

    return !!userRole;
  }

  private async checkApprovalCompletion(invoiceId: string, workflow: ApprovalWorkflow): Promise<boolean> {
    const approvals = await this.prisma.invoiceApproval.findMany({
      where: { invoiceId },
    });

    const requiredLevels = workflow.approvers.filter(level => level.required);
    const completedLevels = approvals.map(a => a.level);

    return requiredLevels.every(level => completedLevels.includes(level.level));
  }

  private async progressToNextApprovalLevel(invoiceId: string): Promise<void> {
    // This would create tasks for the next approval level
    this.logger.log(`Progressing invoice ${invoiceId} to next approval level`);
  }

  private async exportToAccounting(invoice: any): Promise<void> {
    // Export approved invoice to accounting system (QuickBooks, Sage, etc.)
    const exportData = {
      vendor: invoice.vendorName,
      invoiceNumber: invoice.invoiceNumber,
      date: invoice.invoiceDate,
      amount: invoice.amount,
      glCodes: invoice.glCodes,
      lineItems: invoice.lineItems,
    };

    // This would integrate with accounting system API
    this.logger.log(`Exporting invoice ${invoice.id} to accounting system`, exportData);
  }

  private async createPaymentTask(invoiceId: string): Promise<void> {
    const invoice = await this.prisma.invoice.findUnique({
      where: { id: invoiceId },
      include: { property: true },
    });

    const channel = await this.prisma.channel.findFirst({
      where: {
        propertyId: invoice.propertyId,
        key: 'accounting',
      },
    });

    await this.tasksService.create({
      title: `Process payment: ${invoice.vendorName} - $${invoice.amount}`,
      description: `Approved invoice ready for payment. Due: ${invoice.dueDate}`,
      channelId: channel?.id,
      priority: new Date(invoice.dueDate) < new Date(Date.now() + 3 * 24 * 60 * 60 * 1000) ? 'HIGH' : 'MEDIUM',
      tags: ['ap-automation', 'payment-processing'],
      metadata: {
        invoiceId,
        type: 'PAYMENT_PROCESSING',
      },
    }, { id: 'system' });
  }

  private calculateExtractionConfidence(data: InvoiceData): number {
    let score = 0;
    const maxScore = 100;
    
    if (data.vendorName) score += 25;
    if (data.invoiceNumber) score += 25;
    if (data.amount && data.amount > 0) score += 25;
    if (data.invoiceDate) score += 15;
    if (data.lineItems?.length > 0) score += 10;
    
    return score / maxScore;
  }

  private async notifyInvoiceRejection(invoiceId: string, reason: string): Promise<void> {
    // Implementation to notify relevant parties about rejection
    this.logger.log(`Invoice ${invoiceId} rejected: ${reason}`);
  }
}
