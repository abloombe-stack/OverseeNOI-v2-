// =====================================================
// COMPETITOR SCRAPING SERVICE
// =====================================================

// src/competitor/competitor.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { TasksService } from '../tasks/tasks.service';
import * as puppeteer from 'puppeteer';
import * as cheerio from 'cheerio';

interface CompetitorSite {
  id: string;
  name: string;
  baseUrl: string;
  selectors: SiteSelectors;
  transform: SiteTransforms;
  propertyId: string;
}

interface SiteSelectors {
  listSelector: string;
  fields: {
    floorplan: string;
    bedrooms: string;
    sqft: string;
    listRent: string;
    specialsText?: string;
    feesText?: string;
  };
  pagination?: {
    nextSelector: string;
    maxPages: number;
  };
}

interface SiteTransforms {
  bedrooms?: string;
  sqft?: string;
  listRent?: string;
  concessions?: string;
}

interface CompetitorUnit {
  floorplan: string;
  bedrooms: number;
  bathrooms: number;
  sqft: number;
  listRent: number;
  fees: number;
  specials: string;
  concessions: ConcessionData;
  netEffectiveRent: number;
  pricePerSqft: number;
  availableDate?: Date;
}

interface ConcessionData {
  monthsFree: number;
  percentOff: number;
  upfrontCredit: number;
  leaseTermMonths: number;
}

@Injectable()
export class CompetitorService {
  private readonly logger = new Logger(CompetitorService.name);
  private browser: puppeteer.Browser;

  constructor(
    private prisma: PrismaService,
    private tasksService: TasksService,
  ) {}

  async onModuleInit() {
    this.browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
  }

  async onModuleDestroy() {
    if (this.browser) {
      await this.browser.close();
    }
  }

  @Cron(CronExpression.EVERY_DAY_AT_6AM)
  async runDailyScrape(): Promise<void> {
    this.logger.log('Starting daily competitor scrape');
    
    const properties = await this.prisma.property.findMany({
      include: { portfolio: { include: { company: true } } },
    });

    for (const property of properties) {
      try {
        await this.scrapePropertyCompetitors(property.id);
      } catch (error) {
        this.logger.error(`Failed to scrape competitors for property ${property.id}:`, error);
      }
    }
  }

  async scrapePropertyCompetitors(propertyId: string): Promise<void> {
    const competitorSites = await this.getCompetitorSites(propertyId);
    const allComps: CompetitorUnit[] = [];

    for (const site of competitorSites) {
      try {
        const units = await this.scrapeSite(site);
        allComps.push(...units);
        this.logger.log(`Scraped ${units.length} units from ${site.name}`);
      } catch (error) {
        this.logger.error(`Failed to scrape ${site.name}:`, error);
      }
    }

    if (allComps.length > 0) {
      await this.saveCompSnapshot(propertyId, allComps);
      await this.analyzeCompetitorChanges(propertyId, allComps);
    }
  }

  private async scrapeSite(site: CompetitorSite): Promise<CompetitorUnit[]> {
    const page = await this.browser.newPage();
    const units: CompetitorUnit[] = [];

    try {
      // Set user agent to avoid detection
      await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
      
      let currentPage = 1;
      let hasNextPage = true;
      
      while (hasNextPage && currentPage <= (site.selectors.pagination?.maxPages || 5)) {
        const url = this.buildPageUrl(site.baseUrl, currentPage);
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
        
        // Wait for content to load
        await page.waitForSelector(site.selectors.listSelector, { timeout: 10000 });
        
        const html = await page.content();
        const $ = cheerio.load(html);
        
        // Extract units from current page
        const pageUnits = await this.extractUnitsFromPage($, site);
        units.push(...pageUnits);
        
        // Check for next page
        if (site.selectors.pagination) {
          const nextButton = $(site.selectors.pagination.nextSelector);
          hasNextPage = nextButton.length > 0 && !nextButton.hasClass('disabled');
          currentPage++;
        } else {
          hasNextPage = false;
        }
        
        // Rate limiting
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    } finally {
      await page.close();
    }

    return units;
  }

  private extractUnitsFromPage(
    $: cheerio.CheerioAPI, 
    site: CompetitorSite
  ): CompetitorUnit[] {
    const units: CompetitorUnit[] = [];
    
    $(site.selectors.listSelector).each((_, element) => {
      try {
        const unit = this.extractUnitData($, $(element), site);
        if (unit) {
          units.push(unit);
        }
      } catch (error) {
        this.logger.warn(`Failed to extract unit data:`, error);
      }
    });

    return units;
  }

  private extractUnitData(
    $: cheerio.CheerioAPI,
    $element: cheerio.Cheerio<cheerio.Element>,
    site: CompetitorSite
  ): CompetitorUnit | null {
    const selectors = site.selectors.fields;
    
    // Extract raw data
    const floorplan = this.extractText($element, selectors.floorplan);
    const bedroomsText = this.extractText($element, selectors.bedrooms);
    const sqftText = this.extractText($element, selectors.sqft);
    const rentText = this.extractText($element, selectors.listRent);
    const specialsText = this.extractText($element, selectors.specialsText || '');
    const feesText = this.extractText($element, selectors.feesText || '');

    if (!floorplan || !rentText) {
      return null;
    }

    // Apply transformations
    const bedrooms = this.transformBedrooms(bedroomsText, site.transform);
    const sqft = this.transformSqft(sqftText, site.transform);
    const listRent = this.transformCurrency(rentText, site.transform);
    const fees = this.extractFees(feesText);
    const concessions = this.extractConcessions(specialsText, site.transform);

    // Calculate derived values
    const netEffectiveRent = this.calculateNER(listRent, concessions);
    const pricePerSqft = sqft > 0 ? netEffectiveRent / sqft : 0;

    return {
      floorplan,
      bedrooms,
      bathrooms: this.estimateBathrooms(bedrooms), // Fallback estimation
      sqft,
      listRent,
      fees,
      specials: specialsText,
      concessions,
      netEffectiveRent,
      pricePerSqft,
    };
  }

  private extractText($element: cheerio.Cheerio<cheerio.Element>, selector: string): string {
    if (!selector) return '';
    const el = selector.startsWith('.') || selector.startsWith('#') ? 
      $element.find(selector) : $element.closest('*').find(selector);
    return el.text().trim();
  }

  private transformBedrooms(text: string, transforms: SiteTransforms): number {
    if (!text) return 0;
    
    // Handle common formats: "1 BR", "1BR", "1 Bed", "Studio"
    if (text.toLowerCase().includes('studio')) return 0;
    
    const match = text.match(/(\d+)/);
    return match ? parseInt(match[1]) : 0;
  }

  private transformSqft(text: string, transforms: SiteTransforms): number {
    if (!text) return 0;
    
    // Extract numbers and remove commas
    const cleaned = text.replace(/[^\d]/g, '');
    const sqft = parseInt(cleaned);
    
    // Validate reasonable range for apartments
    return (sqft >= 300 && sqft <= 5000) ? sqft : 0;
  }

  private transformCurrency(text: string, transforms: SiteTransforms): number {
    if (!text) return 0;
    
    // Remove currency symbols and extract number
    const cleaned = text.replace(/[$,]/g, '').match(/\d+/);
    return cleaned ? parseInt(cleaned[0]) : 0;
  }

  private extractFees(feesText: string): number {
    if (!feesText) return 0;
    
    // Look for common fee patterns
    const feeMatch = feesText.match(/\$(\d+)/);
    return feeMatch ? parseInt(feeMatch[1]) : 0;
  }

  private extractConcessions(specialsText: string, transforms: SiteTransforms): ConcessionData {
    const concessions: ConcessionData = {
      monthsFree: 0,
      percentOff: 0,
      upfrontCredit: 0,
      leaseTermMonths: 12, // Default lease term
    };

    if (!specialsText) return concessions;

    const text = specialsText.toLowerCase();

    // Extract months free: "1 month free", "2 months free"
    const monthsFreeMatch = text.match(/(\d+)\s*months?\s*free/);
    if (monthsFreeMatch) {
      concessions.monthsFree = parseInt(monthsFreeMatch[1]);
    }

    // Extract percentage off: "50% off", "25% discount"
    const percentMatch = text.match(/(\d+)%\s*(?:off|discount)/);
    if (percentMatch) {
      concessions.percentOff = parseInt(percentMatch[1]);
    }

    // Extract upfront credit: "$500 off", "$1000 credit"
    const creditMatch = text.match(/\$(\d+)\s*(?:off|credit|cashback)/);
    if (creditMatch) {
      concessions.upfrontCredit = parseInt(creditMatch[1]);
    }

    // Extract lease term if specified
    const termMatch = text.match(/(\d+)\s*month\s*lease/);
    if (termMatch) {
      concessions.leaseTermMonths = parseInt(termMatch[1]);
    }

    return concessions;
  }

  private calculateNER(listRent: number, concessions: ConcessionData): number {
    const { monthsFree, percentOff, upfrontCredit, leaseTermMonths } = concessions;
    
    let totalRent = listRent * leaseTermMonths;
    
    // Apply months free
    totalRent -= (listRent * monthsFree);
    
    // Apply percentage discount
    if (percentOff > 0) {
      totalRent *= (1 - percentOff / 100);
    }
    
    // Apply upfront credit
    totalRent -= upfrontCredit;
    
    return totalRent / leaseTermMonths;
  }

  private estimateBathrooms(bedrooms: number): number {
    // Rough estimation based on industry standards
    if (bedrooms === 0) return 1; // Studio
    if (bedrooms === 1) return 1;
    if (bedrooms === 2) return 2;
    return bedrooms; // 3+ bedrooms typically have 2+ baths
  }

  private buildPageUrl(baseUrl: string, page: number): string {
    if (page === 1) return baseUrl;
    
    // Handle common pagination patterns
    const separator = baseUrl.includes('?') ? '&' : '?';
    return `${baseUrl}${separator}page=${page}`;
  }

  private async saveCompSnapshot(propertyId: string, units: CompetitorUnit[]): Promise<void> {
    const snapshot = {
      propertyId,
      date: new Date(),
      comps: {
        units,
        aggregates: this.calculateCompAggregates(units),
        scrapedAt: new Date(),
      },
    };

    await this.prisma.compSnapshot.create({
      data: snapshot,
    });
  }

  private calculateCompAggregates(units: CompetitorUnit[]): any {
    const bedrooms = units.reduce((acc, unit) => {
      acc[unit.bedrooms] = acc[unit.bedrooms] || [];
      acc[unit.bedrooms].push(unit);
      return acc;
    }, {} as Record<number, CompetitorUnit[]>);

    const aggregates: any = {
      totalUnits: units.length,
      byBedrooms: {},
    };

    for (const [br, brUnits] of Object.entries(bedrooms)) {
      const rents = brUnits.map(u => u.netEffectiveRent).filter(r => r > 0);
      const sqfts = brUnits.map(u => u.sqft).filter(s => s > 0);
      const psfs = brUnits.map(u => u.pricePerSqft).filter(p => p > 0);

      aggregates.byBedrooms[br] = {
        count: brUnits.length,
        avgRent: rents.length ? rents.reduce((a, b) => a + b, 0) / rents.length : 0,
        minRent: rents.length ? Math.min(...rents) : 0,
        maxRent: rents.length ? Math.max(...rents) : 0,
        avgSqft: sqfts.length ? sqfts.reduce((a, b) => a + b, 0) / sqfts.length : 0,
        avgPsf: psfs.length ? psfs.reduce((a, b) => a + b, 0) / psfs.length : 0,
      };
    }

    return aggregates;
  }

  private async analyzeCompetitorChanges(propertyId: string, currentComps: CompetitorUnit[]): Promise<void> {
    // Get previous snapshot for comparison
    const previousSnapshot = await this.prisma.compSnapshot.findFirst({
      where: { propertyId },
      orderBy: { date: 'desc' },
      skip: 1, // Skip the current one we just created
    });

    if (!previousSnapshot) return;

    const previousComps = previousSnapshot.comps.units as CompetitorUnit[];
    const significantChanges = this.detectSignificantChanges(previousComps, currentComps);

    for (const change of significantChanges) {
      await this.createRentUpdateTask(propertyId, change);
    }
  }

  private detectSignificantChanges(previous: CompetitorUnit[], current: CompetitorUnit[]): any[] {
    const changes: any[] = [];
    const threshold = 0.05; // 5% change threshold

    // Group by floorplan for comparison
    const previousByFloorplan = new Map(previous.map(u => [u.floorplan, u]));
    
    for (const currentUnit of current) {
      const previousUnit = previousByFloorplan.get(currentUnit.floorplan);
      if (!previousUnit) continue;

      const rentChange = (currentUnit.netEffectiveRent - previousUnit.netEffectiveRent) / previousUnit.netEffectiveRent;
      
      if (Math.abs(rentChange) >= threshold) {
        changes.push({
          floorplan: currentUnit.floorplan,
          bedrooms: currentUnit.bedrooms,
          previousRent: previousUnit.netEffectiveRent,
          currentRent: currentUnit.netEffectiveRent,
          changePercent: rentChange * 100,
          changeDollar: currentUnit.netEffectiveRent - previousUnit.netEffectiveRent,
        });
      }
    }

    return changes.filter(c => Math.abs(c.changePercent) >= 5); // Only significant changes
  }

  private async createRentUpdateTask(propertyId: string, change: any): Promise<void> {
    const channel = await this.prisma.channel.findFirst({
      where: { propertyId, key: 'leasing' },
    });

    if (!channel) return;

    const direction = change.changeDollar > 0 ? 'increased' : 'decreased';
    const title = `Competitor rent ${direction} - ${change.floorplan}`;
    const description = `Competitor ${change.floorplan} rents ${direction} by $${Math.abs(change.changeDollar)} (${Math.abs(change.changePercent).toFixed(1)}%). Previous: $${change.previousRent}, Current: $${change.currentRent}. Consider reviewing our pricing.`;

    await this.tasksService.create({
      title,
      description,
      channelId: channel.id,
      priority: Math.abs(change.changePercent) > 10 ? 'HIGH' : 'MEDIUM',
      tags: ['competitor-analysis', 'pricing', 'auto-generated'],
      metadata: { competitorChange: change },
    }, { id: 'system' });
  }

  private async getCompetitorSites(propertyId: string): Promise<CompetitorSite[]> {
    // In production, this would come from the database
    // For now, return sample competitor configurations
    return [
      {
        id: 'comp1',
        name: 'Nearby Complex A',
        baseUrl: 'https://example-competitor-a.com/apartments',
        propertyId,
        selectors: {
          listSelector: '.unit-card',
          fields: {
            floorplan: '.floorplan-name',
            bedrooms: '.bedrooms',
            sqft: '.square-feet',
            listRent: '.price',
            specialsText: '.specials, .promotion',
            feesText: '.fees',
          },
          pagination: {
            nextSelector: '.pagination .next:not(.disabled)',
            maxPages: 10,
          },
        },
        transform: {
          bedrooms: 'parseBedrooms',
          sqft: 'parseSqft',
          listRent: 'parseCurrency',
          concessions: 'extractConcessionFromSpecials',
        },
      },
    ];
  }
}

// =====================================================
// AI ASSISTANT SERVICE
// =====================================================

// src/ai/ai.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { TasksService } from '../tasks/tasks.service';
import OpenAI from 'openai';

interface AIContext {
  property: any;
  channel: any;
  recentMessages: any[];
  recentTasks: any[];
  rentRollData?: any;
  competitorData?: any;
  userRole: string;
}

interface TaskSuggestion {
  title: string;
  description: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  assigneeId?: string;
  tags: string[];
  reasoning: string;
}

@Injectable()
export class AIService {
  private readonly logger = new Logger(AIService.name);
  private openai: OpenAI;

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {
    this.openai = new OpenAI({
      apiKey: this.configService.get<string>('OPENAI_API_KEY'),
    });
  }

  async generateTaskSuggestions(context: AIContext): Promise<TaskSuggestion[]> {
    const prompt = this.buildTaskSuggestionPrompt(context);
    
    try {
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `You are an AI assistant for property management operations. Analyze the provided context and suggest actionable tasks that would improve operations, revenue, or compliance. Focus on practical, specific tasks that property management staff can execute.`,
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        functions: [
          {
            name: 'suggest_tasks',
            description: 'Suggest actionable tasks for property management',
            parameters: {
              type: 'object',
              properties: {
                tasks: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      title: { type: 'string' },
                      description: { type: 'string' },
                      priority: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
                      category: { type: 'string' },
                      reasoning: { type: 'string' },
                      tags: {
                        type: 'array',
                        items: { type: 'string' },
                      },
                    },
                    required: ['title', 'description', 'priority', 'reasoning', 'tags'],
                  },
                },
              },
            },
          },
        ],
        function_call: { name: 'suggest_tasks' },
        temperature: 0.7,
      });

      const functionCall = completion.choices[0].message.function_call;
      if (functionCall?.arguments) {
        const parsed = JSON.parse(functionCall.arguments);
        return parsed.tasks || [];
      }
    } catch (error) {
      this.logger.error('Failed to generate task suggestions:', error);
    }

    return [];
  }

  async analyzePhoto(imageBuffer: Buffer, context: any): Promise<any> {
    try {
      // Convert image to base64
      const base64Image = imageBuffer.toString('base64');
      
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4-vision-preview',
        messages: [
          {
            role: 'user',
            content: [
              {
                type: 'text',
                text: `Analyze this property image for: 1) Safety issues 2) Maintenance needs 3) Curb appeal improvements 4) Code violations. Property context: ${JSON.stringify(context)}`,
              },
              {
                type: 'image_url',
                image_url: {
                  url: `data:image/jpeg;base64,${base64Image}`,
                },
              },
            ],
          },
        ],
        functions: [
          {
            name: 'analyze_property_image',
            description: 'Analyze property image for issues and improvements',
            parameters: {
              type: 'object',
              properties: {
                safetyIssues: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      issue: { type: 'string' },
                      severity: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
                      location: { type: 'string' },
                      recommendation: { type: 'string' },
                    },
                  },
                },
                maintenanceNeeds: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      item: { type: 'string' },
                      urgency: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH'] },
                      estimatedCost: { type: 'string' },
                      description: { type: 'string' },
                    },
                  },
                },
                curbAppealSuggestions: {
                  type: 'array',
                  items: { type: 'string' },
                },
                codeViolations: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      violation: { type: 'string' },
                      code: { type: 'string' },
                      action: { type: 'string' },
                    },
                  },
                },
                overallCondition: { type: 'string' },
                recommendedActions: {
                  type: 'array',
                  items: { type: 'string' },
                },
              },
            },
          },
        ],
        function_call: { name: 'analyze_property_image' },
        max_tokens: 1000,
      });

      const functionCall = completion.choices[0].message.function_call;
      if (functionCall?.arguments) {
        return JSON.parse(functionCall.arguments);
      }
    } catch (error) {
      this.logger.error('Failed to analyze photo:', error);
    }

    return null;
  }

  async auditLease(leaseDocument: string, context: any): Promise<any> {
    try {
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `You are a lease auditing expert. Review the lease document for completeness, accuracy, and compliance issues. Focus on: missing signatures, incorrect dates, rent calculations, required clauses, and legal compliance.`,
          },
          {
            role: 'user',
            content: `Audit this lease document:\n\n${leaseDocument}\n\nProperty context: ${JSON.stringify(context)}`,
          },
        ],
        functions: [
          {
            name: 'audit_lease',
            description: 'Audit lease document for issues',
            parameters: {
              type: 'object',
              properties: {
                missingSignatures: {
                  type: 'array',
                  items: { type: 'string' },
                },
                dateIssues: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      field: { type: 'string' },
                      issue: { type: 'string' },
                      suggestion: { type: 'string' },
                    },
                  },
                },
                calculationErrors: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      field: { type: 'string' },
                      expected: { type: 'string' },
                      actual: { type: 'string' },
                      correction: { type: 'string' },
                    },
                  },
                },
                missingClauses: {
                  type: 'array',
                  items: { type: 'string' },
                },
                complianceIssues: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      issue: { type: 'string' },
                      regulation: { type: 'string' },
                      remedy: { type: 'string' },
                    },
                  },
                },
                overallRisk: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH'] },
                recommendedActions: {
                  type: 'array',
                  items: { type: 'string' },
                },
              },
            },
          },
        ],
        function_call: { name: 'audit_lease' },
        temperature: 0.3, // Lower temperature for accuracy
      });

      const functionCall = completion.choices[0].message.function_call;
      if (functionCall?.arguments) {
        return JSON.parse(functionCall.arguments);
      }
    } catch (error) {
      this.logger.error('Failed to audit lease:', error);
    }

    return null;
  }

  async generateTaskSummary(taskContext: any): Promise<string> {
    try {
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `Generate a concise, professional summary of a completed task based on the task details and conversation thread. Focus on what was accomplished, key decisions made, and any follow-up items.`,
          },
          {
            role: 'user',
            content: `Task: ${taskContext.title}\nDescription: ${taskContext.description}\n\nConversation thread:\n${taskContext.messages.map(m => `${m.author}: ${m.content}`).join('\n')}\n\nGenerate a brief completion summary.`,
          },
        ],
        max_tokens: 200,
        temperature: 0.5,
      });

      return completion.choices[0].message.content?.trim() || 'Task completed successfully.';
    } catch (error) {
      this.logger.error('Failed to generate task summary:', error);
      return 'Task completed successfully.';
    }
  }

  async analyzeFinancialPerformance(propertyId: string): Promise<any> {
    const rentRollSnapshot = await this.prisma.rentRollSnapshot.findFirst({
      where: { propertyId },
      orderBy: { date: 'desc' },
    });

    if (!rentRollSnapshot) return null;

    const aggregates = rentRollSnapshot.aggregates as any;
    const units = rentRollSnapshot.units as any[];

    const analysis = {
      occupancyRate: (aggregates.occupied_units / aggregates.total_units) * 100,
      totalDelinquency: aggregates.total_balance,
      avgRentPerUnit: aggregates.total_actual_rent / aggregates.total_units,
      rentToMarketRatio: aggregates.total_actual_rent / aggregates.total_market_rent,
      delinquencyRate: (aggregates.delinquency_30 + aggregates.delinquency_60 + aggregates.delinquency_90_plus) / aggregates.total_units * 100,
    };

    return this.generateFinancialInsights(analysis, units);
  }

  private async generateFinancialInsights(analysis: any, units: any[]): Promise<any> {
    try {
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `You are a property financial analyst. Analyze the financial metrics and provide actionable insights and recommendations for improving NOI (Net Operating Income).`,
          },
          {
            role: 'user',
            content: `Financial Analysis:\n${JSON.stringify(analysis, null, 2)}\n\nProvide insights and recommendations to improve property performance.`,
          },
        ],
        functions: [
          {
            name: 'financial_insights',
            description: 'Generate financial insights and recommendations',
            parameters: {
              type: 'object',
              properties: {
                insights: {
                  type: 'array',
                  items: { type: 'string' },
                },
                recommendations: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      action: { type: 'string' },
                      impact: { type: 'string' },
                      timeframe: { type: 'string' },
                      priority: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH'] },
                    },
                  },
                },
                riskFactors: {
                  type: 'array',
                  items: { type: 'string' },
                },
                kpiTargets: {
                  type: 'object',
                  properties: {
                    occupancyTarget: { type: 'number' },
                    delinquencyTarget: { type: 'number' },
                    rentGrowthTarget: { type: 'number' },
                  },
                },
              },
            },
          },
        ],
        function_call: { name: 'financial_insights' },
        temperature: 0.7,
      });

      const functionCall = completion.choices[0].message.function_call;
      if (functionCall?.arguments) {
        return JSON.parse(functionCall.arguments);
      }
    } catch (error) {
      this.logger.error('Failed to generate financial insights:', error);
    }

    return null;
  }

  private buildTaskSuggestionPrompt(context: AIContext): string {
    const sections = [
      `Property: ${context.property.name} (${context.property.unitCount} units)`,
      `Current Channel: ${context.channel.name}`,
      `User Role: ${context.userRole}`,
    ];

    if (context.recentMessages.length > 0) {
      sections.push(`Recent Messages:\n${context.recentMessages.map(m => `- ${m.author}: ${m.content}`).join('\n')}`);
    }

    if (context.recentTasks.length > 0) {
      sections.push(`Recent Tasks:\n${context.recentTasks.map(t => `- ${t.title} (${t.status})`).join('\n')}`);
    }

    if (context.rentRollData) {
      sections.push(`Rent Roll Data:\n${JSON.stringify(context.rentRollData, null, 2)}`);
    }

    if (context.competitorData) {
      sections.push(`Competitor Data:\n${JSON.stringify(context.competitorData, null, 2)}`);
    }

    return sections.join('\n\n');
  }

  async processVoiceToTask(audioBuffer: Buffer, context: any): Promise<any> {
    try {
      // Transcribe audio using Whisper
      const transcription = await this.openai.audio.transcriptions.create({
        file: new File([audioBuffer], 'audio.wav', { type: 'audio/wav' }),
        model: 'whisper-1',
      });

      const transcript = transcription.text;

      // Extract task information from transcript
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `Extract task information from voice transcripts. Convert natural speech into structured task data for property management.`,
          },
          {
            role: 'user',
            content: `Voice transcript: "${transcript}"\n\nContext: ${JSON.stringify(context)}\n\nExtract task details.`,
          },
        ],
        functions: [
          {
            name: 'extract_task',
            description: 'Extract task information from voice transcript',
            parameters: {
              type: 'object',
              properties: {
                title: { type: 'string' },
                description: { type: 'string' },
                priority: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
                dueDate: { type: 'string' },
                assignee: { type: 'string' },
                tags: {
                  type: 'array',
                  items: { type: 'string' },
                },
                location: { type: 'string' },
                transcript: { type: 'string' },
              },
              required: ['title', 'description', 'transcript'],
            },
          },
        ],
        function_call: { name: 'extract_task' },
      });

      const functionCall = completion.choices[0].message.function_call;
      if (functionCall?.arguments) {
        const taskData = JSON.parse(functionCall.arguments);
        return {
          ...taskData,
          originalTranscript: transcript,
        };
      }
    } catch (error) {
      this.logger.error('Failed to process voice to task:', error);
    }

    return null;
  }

  async generateMeetingMinutes(transcript: string, attendees: string[]): Promise<string> {
    try {
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `Generate professional meeting minutes from a transcript. Include key decisions, action items with owners, and important discussions.`,
          },
          {
            role: 'user',
            content: `Meeting transcript:\n${transcript}\n\nAttendees: ${attendees.join(', ')}\n\nGenerate meeting minutes.`,
          },
        ],
        temperature: 0.3,
      });

      return completion.choices[0].message.content || 'Unable to generate meeting minutes.';
    } catch (error) {
      this.logger.error('Failed to generate meeting minutes:', error);
      return 'Unable to generate meeting minutes.';
    }
  }

  async detectBudgetRisk(expenses: any[], budget: any): Promise<any> {
    try {
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `Analyze expense patterns and budget data to identify spending risks and suggest cost control measures.`,
          },
          {
            role: 'user',
            content: `Expenses: ${JSON.stringify(expenses)}\nBudget: ${JSON.stringify(budget)}\n\nAnalyze for budget risks.`,
          },
        ],
        functions: [
          {
            name: 'budget_risk_analysis',
            description: 'Analyze budget risks and recommendations',
            parameters: {
              type: 'object',
              properties: {
                risks: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      category: { type: 'string' },
                      riskLevel: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH'] },
                      projectedOverage: { type: 'number' },
                      reasoning: { type: 'string' },
                    },
                  },
                },
                recommendations: {
                  type: 'array',
                  items: { type: 'string' },
                },
                alertThresholds: {
                  type: 'object',
                  properties: {
                    immediate: { type: 'number' },
                    warning: { type: 'number' },
                  },
                },
              },
            },
          },
        ],
        function_call: { name: 'budget_risk_analysis' },
      });

      const functionCall = completion.choices[0].message.function_call;
      if (functionCall?.arguments) {
        return JSON.parse(functionCall.arguments);
      }
    } catch (error) {
      this.logger.error('Failed to detect budget risk:', error);
    }

    return null;
  }
}