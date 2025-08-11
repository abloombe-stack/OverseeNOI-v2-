// =====================================================
// DATABASE SCHEMA (Prisma)
// =====================================================

// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model Company {
  id        String   @id @default(cuid())
  name      String
  settings  Json?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  portfolios Portfolio[]
  users      User[]

  @@map("companies")
}

model Portfolio {
  id        String   @id @default(cuid())
  name      String
  companyId String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  company    Company    @relation(fields: [companyId], references: [id], onDelete: Cascade)
  properties Property[]

  @@map("portfolios")
}

model Property {
  id           String  @id @default(cuid())
  name         String
  address      String
  unitCount    Int
  propertyType String
  portfolioId  String
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt

  portfolio         Portfolio           @relation(fields: [portfolioId], references: [id], onDelete: Cascade)
  channels          Channel[]
  rentRollSnapshots RentRollSnapshot[]
  compSnapshots     CompSnapshot[]
  userRoles         UserRole[]

  @@map("properties")
}

model User {
  id          String   @id @default(cuid())
  email       String   @unique
  displayName String
  avatar      String?
  companyId   String
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt

  company         Company       @relation(fields: [companyId], references: [id], onDelete: Cascade)
  roles           UserRole[]
  assignedTasks   Task[]        @relation("TaskAssignee")
  createdTasks    Task[]        @relation("TaskCreator")
  messages        Message[]
  activityEvents  ActivityEvent[]

  @@map("users")
}

model UserRole {
  id         String @id @default(cuid())
  userId     String
  propertyId String?
  role       Role
  scope      Json

  user     User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  property Property? @relation(fields: [propertyId], references: [id], onDelete: Cascade)

  @@unique([userId, propertyId, role])
  @@map("user_roles")
}

enum Role {
  VP
  DIRECTOR
  ASSET_MANAGER
  SENIOR_ANALYST
  CAPEX_PM
  REGIONAL_PM
  PROPERTY_MANAGER
  ASSISTANT_PM_AR
  LEASING_MANAGER
  LEASING_AGENT
  MAINTENANCE_SUPER
  MAINTENANCE_TECH
  VENDOR
}

model Channel {
  id              String   @id @default(cuid())
  key             String
  name            String
  propertyId      String
  visibilityRoles String[]
  createdAt       DateTime @default(now())
  updatedAt       DateTime @updatedAt

  property Property  @relation(fields: [propertyId], references: [id], onDelete: Cascade)
  messages Message[]
  tasks    Task[]

  @@unique([propertyId, key])
  @@map("channels")
}

model Message {
  id          String   @id @default(cuid())
  content     String
  channelId   String?
  taskId      String?
  authorId    String
  attachments String[]
  isSystem    Boolean  @default(false)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt

  channel Channel? @relation(fields: [channelId], references: [id], onDelete: Cascade)
  task    Task?    @relation(fields: [taskId], references: [id], onDelete: Cascade)
  author  User     @relation(fields: [authorId], references: [id], onDelete: Cascade)

  @@map("messages")
}

model Task {
  id          String     @id @default(cuid())
  title       String
  description String?
  status      TaskStatus @default(OPEN)
  priority    Priority   @default(MEDIUM)
  channelId   String
  assigneeId  String?
  createdById String
  dueAt       DateTime?
  slaAt       DateTime?
  tags        String[]
  metadata    Json?
  createdAt   DateTime   @default(now())
  updatedAt   DateTime   @updatedAt

  channel   Channel   @relation(fields: [channelId], references: [id], onDelete: Cascade)
  assignee  User?     @relation("TaskAssignee", fields: [assigneeId], references: [id])
  createdBy User      @relation("TaskCreator", fields: [createdById], references: [id], onDelete: Cascade)
  messages  Message[]
  events    TaskEvent[]

  @@map("tasks")
}

enum TaskStatus {
  OPEN
  IN_PROGRESS
  SCHEDULED
  COMPLETED
  CANCELLED
}

enum Priority {
  LOW
  MEDIUM
  HIGH
  CRITICAL
}

model TaskEvent {
  id       String          @id @default(cuid())
  taskId   String
  type     TaskEventType
  delta    Json?
  metadata Json?
  createdAt DateTime      @default(now())

  task Task @relation(fields: [taskId], references: [id], onDelete: Cascade)

  @@map("task_events")
}

enum TaskEventType {
  CREATED
  ASSIGNED
  STATUS_CHANGED
  PRIORITY_CHANGED
  DUE_DATE_CHANGED
  COMPLETED
  COMMENTED
}

model RentRollSnapshot {
  id         String   @id @default(cuid())
  propertyId String
  date       DateTime
  units      Json
  aggregates Json
  createdAt  DateTime @default(now())

  property Property        @relation(fields: [propertyId], references: [id], onDelete: Cascade)
  diffs    RentRollDiff[]  @relation("SnapshotA")
  diffsB   RentRollDiff[]  @relation("SnapshotB")

  @@unique([propertyId, date])
  @@map("rent_roll_snapshots")
}

model RentRollDiff {
  id           String   @id @default(cuid())
  propertyId   String
  date         DateTime
  snapshotAId  String
  snapshotBId  String
  deltas       Json
  aggregates   Json
  createdAt    DateTime @default(now())

  snapshotA RentRollSnapshot @relation("SnapshotA", fields: [snapshotAId], references: [id])
  snapshotB RentRollSnapshot @relation("SnapshotB", fields: [snapshotBId], references: [id])

  @@unique([propertyId, date])
  @@map("rent_roll_diffs")
}

model CompSnapshot {
  id         String   @id @default(cuid())
  propertyId String
  date       DateTime
  comps      Json
  createdAt  DateTime @default(now())

  property Property @relation(fields: [propertyId], references: [id], onDelete: Cascade)

  @@unique([propertyId, date])
  @@map("comp_snapshots")
}

model ActivityEvent {
  id       String   @id @default(cuid())
  userId   String
  context  Json
  action   String
  duration Int?
  success  Boolean  @default(true)
  metadata Json?
  createdAt DateTime @default(now())

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("activity_events")
}

// =====================================================
// NESTJS APPLICATION STRUCTURE
// =====================================================

// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { PropertiesModule } from './properties/properties.module';
import { ChannelsModule } from './channels/channels.module';
import { TasksModule } from './tasks/tasks.module';
import { RentRollModule } from './rent-roll/rent-roll.module';
import { CompetitorModule } from './competitor/competitor.module';
import { ActivityModule } from './activity/activity.module';
import { NotificationModule } from './notification/notification.module';
import { FilesModule } from './files/files.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,
      subscriptions: {
        'graphql-ws': true,
      },
      context: ({ req, connection }) => {
        return { req: req || connection.context };
      },
    }),
    PrismaModule,
    AuthModule,
    UsersModule,
    PropertiesModule,
    ChannelsModule,
    TasksModule,
    RentRollModule,
    CompetitorModule,
    ActivityModule,
    NotificationModule,
    FilesModule,
  ],
})
export class AppModule {}

// =====================================================
// GRAPHQL RESOLVERS & SERVICES
// =====================================================

// src/tasks/tasks.resolver.ts
import { Resolver, Query, Mutation, Args, Subscription, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { PubSub } from 'graphql-subscriptions';
import { AuthGuard } from '../auth/auth.guard';
import { RBACGuard } from '../auth/rbac.guard';
import { TasksService } from './tasks.service';
import { Task, CreateTaskInput, UpdateTaskInput, TaskFilters } from './task.model';

const pubSub = new PubSub();

@Resolver(() => Task)
@UseGuards(AuthGuard, RBACGuard)
export class TasksResolver {
  constructor(private tasksService: TasksService) {}

  @Query(() => [Task])
  async tasks(
    @Args('channelId') channelId: string,
    @Args('filters', { nullable: true }) filters?: TaskFilters,
    @Context() context?: any,
  ): Promise<Task[]> {
    return this.tasksService.findByChannel(channelId, filters, context.user);
  }

  @Mutation(() => Task)
  async createTask(
    @Args('input') input: CreateTaskInput,
    @Context() context: any,
  ): Promise<Task> {
    const task = await this.tasksService.create(input, context.user);
    
    // Publish to subscriptions
    pubSub.publish('taskCreated', { taskCreated: task });
    
    // Trigger notifications
    this.tasksService.notifyTaskAssignment(task);
    
    return task;
  }

  @Mutation(() => Task)
  async completeTask(
    @Args('id') id: string,
    @Context() context: any,
  ): Promise<Task> {
    const task = await this.tasksService.complete(id, context.user);
    
    // Auto-generate AI summary
    const summary = await this.tasksService.generateCompletionSummary(task);
    await this.tasksService.postSummaryMessage(task.channelId, summary);
    
    pubSub.publish('taskUpdated', { taskUpdated: task });
    
    return task;
  }

  @Subscription(() => Task, {
    filter: (payload, variables) => {
      return payload.taskUpdated.channelId === variables.channelId;
    },
  })
  taskUpdated(@Args('channelId') channelId: string) {
    return pubSub.asyncIterator('taskUpdated');
  }
}

// src/tasks/tasks.service.ts
import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AIService } from '../ai/ai.service';
import { NotificationService } from '../notification/notification.service';
import { RBACService } from '../auth/rbac.service';
import { Task, CreateTaskInput, UpdateTaskInput, TaskFilters, TaskStatus } from './task.model';

@Injectable()
export class TasksService {
  constructor(
    private prisma: PrismaService,
    private aiService: AIService,
    private notificationService: NotificationService,
    private rbacService: RBACService,
  ) {}

  async findByChannel(channelId: string, filters?: TaskFilters, user?: any): Promise<Task[]> {
    // Verify user has access to this channel
    const channel = await this.prisma.channel.findUnique({
      where: { id: channelId },
      include: { property: true },
    });
    
    if (!this.rbacService.canAccessProperty(user, channel.propertyId)) {
      throw new ForbiddenException('Insufficient permissions');
    }

    const where: any = { channelId };
    
    if (filters?.status) where.status = filters.status;
    if (filters?.assigneeId) where.assigneeId = filters.assigneeId;
    if (filters?.priority) where.priority = filters.priority;
    
    return this.prisma.task.findMany({
      where,
      include: {
        assignee: true,
        createdBy: true,
        messages: {
          include: { author: true },
          orderBy: { createdAt: 'asc' },
        },
      },
      orderBy: [
        { priority: 'desc' },
        { createdAt: 'desc' },
      ],
    });
  }

  async create(input: CreateTaskInput, user: any): Promise<Task> {
    // Verify permissions
    const channel = await this.prisma.channel.findUnique({
      where: { id: input.channelId },
      include: { property: true },
    });
    
    if (!this.rbacService.canCreateTask(user, channel.propertyId, channel.key)) {
      throw new ForbiddenException('Insufficient permissions');
    }

    const task = await this.prisma.task.create({
      data: {
        ...input,
        createdById: user.id,
        slaAt: this.calculateSLA(input.priority, input.dueAt),
      },
      include: {
        assignee: true,
        createdBy: true,
        channel: { include: { property: true } },
      },
    });

    // Log task creation event
    await this.prisma.taskEvent.create({
      data: {
        taskId: task.id,
        type: 'CREATED',
        delta: { initial_state: task },
      },
    });

    return task;
  }

  async complete(id: string, user: any): Promise<Task> {
    const task = await this.prisma.task.findUnique({
      where: { id },
      include: { channel: { include: { property: true } } },
    });

    if (!this.rbacService.canCompleteTask(user, task)) {
      throw new ForbiddenException('Insufficient permissions');
    }

    const updatedTask = await this.prisma.task.update({
      where: { id },
      data: { 
        status: TaskStatus.COMPLETED,
        updatedAt: new Date(),
      },
      include: {
        assignee: true,
        createdBy: true,
        messages: { include: { author: true } },
      },
    });

    // Log completion event
    await this.prisma.taskEvent.create({
      data: {
        taskId: id,
        type: 'COMPLETED',
        delta: { completed_by: user.id, completed_at: new Date() },
      },
    });

    return updatedTask;
  }

  async generateCompletionSummary(task: Task): Promise<string> {
    const context = {
      title: task.title,
      description: task.description,
      messages: task.messages.map(m => ({
        author: m.author.displayName,
        content: m.content,
        timestamp: m.createdAt,
      })),
    };

    return this.aiService.generateTaskSummary(context);
  }

  async postSummaryMessage(channelId: string, summary: string): Promise<void> {
    await this.prisma.message.create({
      data: {
        content: `✅ **Task Completed** - ${summary}`,
        channelId,
        authorId: 'system', // System user ID
        isSystem: true,
      },
    });
  }

  async notifyTaskAssignment(task: Task): Promise<void> {
    if (task.assigneeId) {
      await this.notificationService.send({
        userId: task.assigneeId,
        type: 'TASK_ASSIGNED',
        title: 'New Task Assigned',
        message: `You've been assigned: ${task.title}`,
        data: { taskId: task.id, channelId: task.channelId },
      });
    }
  }

  private calculateSLA(priority: Priority, dueAt?: Date): Date | null {
    if (!dueAt) return null;
    
    const slaHours = {
      CRITICAL: 4,
      HIGH: 24,
      MEDIUM: 72,
      LOW: 168,
    };

    const sla = new Date(dueAt);
    sla.setHours(sla.getHours() - slaHours[priority]);
    return sla;
  }
}

// =====================================================
// RENT ROLL PROCESSING
// =====================================================

// src/rent-roll/rent-roll.service.ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { TasksService } from '../tasks/tasks.service';
import * as Papa from 'papaparse';

@Injectable()
export class RentRollService {
  constructor(
    private prisma: PrismaService,
    private tasksService: TasksService,
  ) {}

  async processUpload(propertyId: string, fileBuffer: Buffer, filename: string): Promise<string> {
    const csvContent = fileBuffer.toString('utf-8');
    const parsed = Papa.parse(csvContent, {
      header: true,
      dynamicTyping: true,
      skipEmptyLines: true,
    });

    // Normalize column headers and map to canonical format
    const normalizedData = this.normalizeRentRollData(parsed.data);
    
    // Create snapshot
    const snapshot = await this.prisma.rentRollSnapshot.create({
      data: {
        propertyId,
        date: new Date(),
        units: normalizedData.units,
        aggregates: normalizedData.aggregates,
      },
    });

    // Compare with previous snapshot if exists
    const previousSnapshot = await this.prisma.rentRollSnapshot.findFirst({
      where: { 
        propertyId,
        date: { lt: snapshot.date },
      },
      orderBy: { date: 'desc' },
    });

    if (previousSnapshot) {
      const diff = await this.calculateDiff(previousSnapshot, snapshot);
      await this.processDiffAnomalies(propertyId, diff);
    }

    return snapshot.id;
  }

  private normalizeRentRollData(rawData: any[]): { units: any[], aggregates: any } {
    const units = rawData.map(row => {
      // Map common column variations to canonical fields
      const mapping = this.getColumnMapping(Object.keys(row));
      
      return {
        unit_id: row[mapping.unit_id] || row.Unit || row['Unit #'],
        unit_label: row[mapping.unit_label] || row.Unit,
        bedrooms: parseInt(row[mapping.bedrooms] || row.BR || row.Bedrooms) || 0,
        bathrooms: parseFloat(row[mapping.bathrooms] || row.BA || row.Bathrooms) || 0,
        sqft: parseInt(row[mapping.sqft] || row.SqFt || row['Sq Ft']) || 0,
        tenant_name_masked: this.maskTenantName(row[mapping.tenant] || row.Tenant || row.Resident),
        lease_start: this.parseDate(row[mapping.lease_start] || row['Lease Start'] || row['Lease From']),
        lease_end: this.parseDate(row[mapping.lease_end] || row['Lease End'] || row['Lease To']),
        market_rent: parseFloat(row[mapping.market_rent] || row['Market Rent'] || row.Market) || 0,
        actual_rent: parseFloat(row[mapping.actual_rent] || row['Current Rent'] || row.Rent) || 0,
        balance: parseFloat(row[mapping.balance] || row.Balance || row['AR Balance']) || 0,
        status: this.normalizeStatus(row[mapping.status] || row.Status || row['Occ Status']),
        delinquency_bucket: this.calculateDelinquencyBucket(row[mapping.balance] || 0),
      };
    });

    const aggregates = this.calculateAggregates(units);
    
    return { units, aggregates };
  }

  private async calculateDiff(snapshotA: any, snapshotB: any): Promise<any> {
    const unitsA = new Map(snapshotA.units.map(u => [u.unit_id, u]));
    const unitsB = new Map(snapshotB.units.map(u => [u.unit_id, u]));
    
    const deltas = [];
    
    // Compare each unit
    for (const [unitId, unitB] of unitsB) {
      const unitA = unitsA.get(unitId);
      
      if (!unitA) {
        deltas.push({
          unit_id: unitId,
          type: 'NEW_UNIT',
          severity: 'info',
        });
        continue;
      }

      // Check for significant changes
      const fields = ['balance', 'actual_rent', 'status', 'tenant_name_masked'];
      for (const field of fields) {
        if (unitA[field] !== unitB[field]) {
          const severity = this.getDeltaSeverity(field, unitA[field], unitB[field]);
          deltas.push({
            unit_id: unitId,
            field,
            old_value: unitA[field],
            new_value: unitB[field],
            severity,
            reason_guess: this.guessChangeReason(field, unitA[field], unitB[field]),
          });
        }
      }
    }

    return {
      property_id: snapshotB.propertyId,
      date: snapshotB.date,
      snapshot_a: snapshotA.id,
      snapshot_b: snapshotB.id,
      deltas,
      aggregates: {
        total_deltas: deltas.length,
        balance_change: snapshotB.aggregates.total_balance - snapshotA.aggregates.total_balance,
        move_ins: deltas.filter(d => d.type === 'MOVE_IN').length,
        move_outs: deltas.filter(d => d.type === 'MOVE_OUT').length,
      },
    };
  }

  private async processDiffAnomalies(propertyId: string, diff: any): Promise<void> {
    const highSeverityDeltas = diff.deltas.filter(d => d.severity === 'high');
    
    for (const delta of highSeverityDeltas) {
      // Auto-create investigation tasks for anomalies
      const channel = await this.prisma.channel.findFirst({
        where: { 
          propertyId,
          key: this.getChannelForAnomaly(delta.field),
        },
      });

      if (channel) {
        await this.tasksService.create({
          title: `Investigate ${delta.field} anomaly - Unit ${delta.unit_id}`,
          description: `${delta.field} changed from ${delta.old_value} to ${delta.new_value}. ${delta.reason_guess}`,
          channelId: channel.id,
          priority: 'HIGH',
          tags: ['anomaly', 'auto-generated'],
          metadata: { delta, diff_id: diff.id },
        }, { id: 'system' }); // System user
      }
    }
  }

  // Additional helper methods...
  private getColumnMapping(headers: string[]): any {
    // Map various PMS column names to canonical fields
    const mappings = {
      yardi: {
        unit_id: 'Unit',
        tenant: 'Tenant',
        lease_start: 'Lease From',
        lease_end: 'Lease To',
        market_rent: 'Market Rent',
        actual_rent: 'Current Rent',
        balance: 'Balance',
        status: 'Status',
      },
      realpage: {
        unit_id: 'Unit',
        tenant: 'Resident',
        lease_start: 'Lease Start',
        lease_end: 'Lease End',
        market_rent: 'Market',
        actual_rent: 'Charge Rent',
        balance: 'AR Balance',
        status: 'Occ Status',
      },
      // Add more PMS mappings...
    };
    
    // Auto-detect PMS type and return appropriate mapping
    return this.detectPMSType(headers) || mappings.yardi;
  }

  private detectPMSType(headers: string[]): any {
    // Logic to detect PMS based on header patterns
    if (headers.includes('Lease From') && headers.includes('Lease To')) return 'yardi';
    if (headers.includes('Lease Start') && headers.includes('Lease End')) return 'realpage';
    return null;
  }

  private maskTenantName(name: string): string {
    if (!name) return null;
    return name.split(' ').map(part => part.charAt(0) + '*'.repeat(part.length - 1)).join(' ');
  }

  private calculateDelinquencyBucket(balance: number): string {
    if (balance <= 0) return '0';
    if (balance <= 1000) return '30';
    if (balance <= 2000) return '60';
    return '90+';
  }

  private getDeltaSeverity(field: string, oldVal: any, newVal: any): string {
    if (field === 'balance') {
      const change = Math.abs(newVal - oldVal);
      if (change > 1000) return 'high';
      if (change > 500) return 'medium';
      return 'low';
    }
    return 'medium';
  }

  private guessChangeReason(field: string, oldVal: any, newVal: any): string {
    if (field === 'balance' && newVal > oldVal) {
      return 'Possible missed payment or new charge applied';
    }
    if (field === 'status' && newVal === 'vacant') {
      return 'Unit became vacant - check for proper move-out processing';
    }
    return 'Review required to determine cause';
  }

  private getChannelForAnomaly(field: string): string {
    const mapping = {
      balance: 'ar',
      actual_rent: 'leasing',
      status: 'leasing',
      tenant_name_masked: 'leasing',
    };
    return mapping[field] || 'general';
  }

  private calculateAggregates(units: any[]): any {
    return {
      total_units: units.length,
      occupied_units: units.filter(u => u.status === 'occupied').length,
      total_balance: units.reduce((sum, u) => sum + u.balance, 0),
      total_market_rent: units.reduce((sum, u) => sum + u.market_rent, 0),
      total_actual_rent: units.reduce((sum, u) => sum + u.actual_rent, 0),
      delinquency_30: units.filter(u => u.delinquency_bucket === '30').length,
      delinquency_60: units.filter(u => u.delinquency_bucket === '60').length,
      delinquency_90_plus: units.filter(u => u.delinquency_bucket === '90+').length,
    };
  }

  private parseDate(dateStr: string): Date | null {
    if (!dateStr) return null;
    const date = new Date(dateStr);
    return isNaN(date.getTime()) ? null : date;
  }

  private normalizeStatus(status: string): string {
    if (!status) return 'unknown';
    const normalized = status.toLowerCase().trim();
    if (normalized.includes('occ') || normalized.includes('rented')) return 'occupied';
    if (normalized.includes('vac') || normalized.includes('empty')) return 'vacant';
    if (normalized.includes('notice')) return 'notice';
    return normalized;
  }
}

// =====================================================
// RBAC IMPLEMENTATION
// =====================================================

// src/auth/rbac.service.ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class RBACService {
  constructor(private prisma: PrismaService) {}

  async canAccessProperty(user: any, propertyId: string): Promise<boolean> {
    const role = await this.prisma.userRole.findFirst({
      where: {
        userId: user.id,
        OR: [
          { propertyId },
          { propertyId: null }, // Company-wide access
        ],
      },
    });

    return !!role;
  }

  async canAccessChannel(user: any, propertyId: string, channelKey: string): Promise<boolean> {
    const role = await this.prisma.userRole.findFirst({
      where: {
        userId: user.id,
        OR: [
          { propertyId },
          { propertyId: null },
        ],
      },
    });

    if (!role) return false;

    // Check role-based channel access
    const channelPermissions = this.getChannelPermissions(role.role);
    return channelPermissions.includes(channelKey) || channelPermissions.includes('*');
  }

  async canCreateTask(user: any, propertyId: string, channelKey: string): Promise<boolean> {
    const hasChannelAccess = await this.canAccessChannel(user, propertyId, channelKey);
    if (!hasChannelAccess) return false;

    const role = await this.getUserRole(user.id, propertyId);
    const taskPermissions = this.getTaskPermissions(role.role);
    return taskPermissions.includes('create');
  }

  async canCompleteTask(user: any, task: any): Promise<boolean> {
    // Task assignee or manager can complete
    if (task.assigneeId === user.id) return true;
    
    const role = await this.getUserRole(user.id, task.channel.propertyId);
    const taskPermissions = this.getTaskPermissions(role.role);
    return taskPermissions.includes('complete_any');
  }

  private getChannelPermissions(role: string): string[] {
    const permissions = {
      VP: ['*'],
      DIRECTOR: ['*'],
      ASSET_MANAGER: ['*'],
      SENIOR_ANALYST: ['*'],
      CAPEX_PM: ['capex', 'maintenance'],
      REGIONAL_PM: ['*'],
      PROPERTY_MANAGER: ['*'],
      ASSISTANT_PM_AR: ['ar', 'collections'],
      LEASING_MANAGER: ['leasing', 'marketing'],
      LEASING_AGENT: ['leasing'],
      MAINTENANCE_SUPER: ['maintenance', 'workorders'],
      MAINTENANCE_TECH: ['maintenance'],
      VENDOR: ['bids'],
    };

    return permissions[role] || [];
  }

  private getTaskPermissions(role: string): string[] {
    const permissions = {
      VP: ['create', 'assign', 'complete_any', 'delete'],
      DIRECTOR: ['create', 'assign', 'complete_any', 'delete'],
      ASSET_MANAGER: ['create', 'assign', 'complete_any'],
      REGIONAL_PM: ['create', 'assign', 'complete_any'],
      PROPERTY_MANAGER: ['create', 'assign', 'complete_any'],
      ASSISTANT_PM_AR: ['create', 'complete_own'],
      LEASING_MANAGER: ['create', 'assign', 'complete_any'],
      LEASING_AGENT: ['create', 'complete_own'],
      MAINTENANCE_SUPER: ['create', 'assign', 'complete_any'],
      MAINTENANCE_TECH: ['create', 'complete_own'],
      VENDOR: ['complete_own'],
    };

    return permissions[role] || ['complete_own'];
  }

  private async getUserRole(userId: string, propertyId: string) {
    return this.prisma.userRole.findFirst({
      where: {
        userId,
        OR: [
          { propertyId },
          { propertyId: null },
        ],
      },
      orderBy: { propertyId: 'desc' }, // Property-specific roles take precedence
    });
  }
}