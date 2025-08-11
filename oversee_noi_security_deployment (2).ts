// =====================================================
// SECURITY & AUTHENTICATION IMPLEMENTATION
// =====================================================

// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { RBACGuard } from './rbac.guard';
import { RBACService } from './rbac.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [
    PrismaModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN', '24h'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [AuthService, JwtStrategy, LocalStrategy, RBACGuard, RBACService],
  controllers: [AuthController],
  exports: [AuthService, RBACGuard, RBACService],
})
export class AuthModule {}

// src/auth/auth.service.ts
import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

interface JwtPayload {
  sub: string;
  email: string;
  companyId: string;
  roles: string[];
  iat?: number;
  exp?: number;
}

interface LoginResult {
  user: any;
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: {
        company: true,
        roles: {
          include: { property: true },
        },
      },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if account is active
    if (user.status === 'INACTIVE') {
      throw new UnauthorizedException('Account is inactive');
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if password needs to be changed
    if (user.mustChangePassword) {
      throw new BadRequestException('Password change required');
    }

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        lastLoginAt: new Date(),
        loginCount: { increment: 1 },
      },
    });

    // Remove sensitive information
    const { passwordHash, ...result } = user;
    return result;
  }

  async login(user: any): Promise<LoginResult> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      companyId: user.companyId,
      roles: user.roles.map(r => r.role),
    };

    const accessToken = this.jwtService.sign(payload);
    const refreshToken = await this.generateRefreshToken(user.id);

    return {
      user: {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar,
        company: user.company,
        roles: user.roles,
      },
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(refreshToken: string): Promise<{ accessToken: string }> {
    const tokenRecord = await this.prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: { include: { company: true, roles: true } } },
    });

    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    if (tokenRecord.revoked) {
      throw new UnauthorizedException('Token has been revoked');
    }

    const payload: JwtPayload = {
      sub: tokenRecord.user.id,
      email: tokenRecord.user.email,
      companyId: tokenRecord.user.companyId,
      roles: tokenRecord.user.roles.map(r => r.role),
    };

    const accessToken = this.jwtService.sign(payload);

    // Update last used timestamp
    await this.prisma.refreshToken.update({
      where: { id: tokenRecord.id },
      data: { lastUsedAt: new Date() },
    });

    return { accessToken };
  }

  async logout(userId: string, refreshToken?: string): Promise<void> {
    if (refreshToken) {
      await this.prisma.refreshToken.updateMany({
        where: {
          userId,
          token: refreshToken,
        },
        data: { revoked: true },
      });
    } else {
      // Revoke all refresh tokens for user
      await this.prisma.refreshToken.updateMany({
        where: { userId },
        data: { revoked: true },
      });
    }
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Validate new password strength
    this.validatePasswordStrength(newPassword);

    // Hash new password
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash: newPasswordHash,
        mustChangePassword: false,
        passwordChangedAt: new Date(),
      },
    });

    // Revoke all existing refresh tokens
    await this.prisma.refreshToken.updateMany({
      where: { userId },
      data: { revoked: true },
    });
  }

  async resetPassword(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      // Don't reveal if email exists
      return;
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await this.prisma.passwordReset.create({
      data: {
        userId: user.id,
        tokenHash: resetTokenHash,
        expiresAt,
      },
    });

    // Send reset email (implement email service)
    // await this.emailService.sendPasswordReset(user.email, resetToken);
  }

  async confirmPasswordReset(token: string, newPassword: string): Promise<void> {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    
    const resetRecord = await this.prisma.passwordReset.findFirst({
      where: {
        tokenHash,
        expiresAt: { gte: new Date() },
        used: false,
      },
      include: { user: true },
    });

    if (!resetRecord) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    // Validate new password strength
    this.validatePasswordStrength(newPassword);

    // Hash new password
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update password and mark reset as used
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: resetRecord.userId },
        data: {
          passwordHash: newPasswordHash,
          mustChangePassword: false,
          passwordChangedAt: new Date(),
        },
      }),
      this.prisma.passwordReset.update({
        where: { id: resetRecord.id },
        data: { used: true },
      }),
      // Revoke all refresh tokens
      this.prisma.refreshToken.updateMany({
        where: { userId: resetRecord.userId },
        data: { revoked: true },
      }),
    ]);
  }

  async enableTwoFactor(userId: string): Promise<{ secret: string; qrCode: string }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const secret = crypto.randomBytes(16).toString('base32');
    const qrCode = this.generateTOTPQRCode(user.email, secret);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: secret,
        twoFactorEnabled: false, // Will be enabled after verification
      },
    });

    return { secret, qrCode };
  }

  async verifyTwoFactor(userId: string, token: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user?.twoFactorSecret) {
      return false;
    }

    const isValid = this.verifyTOTPToken(user.twoFactorSecret, token);
    
    if (isValid && !user.twoFactorEnabled) {
      // Enable 2FA after first successful verification
      await this.prisma.user.update({
        where: { id: userId },
        data: { twoFactorEnabled: true },
      });
    }

    return isValid;
  }

  private async generateRefreshToken(userId: string): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await this.prisma.refreshToken.create({
      data: {
        userId,
        token,
        expiresAt,
      },
    });

    return token;
  }

  private validatePasswordStrength(password: string): void {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
      throw new BadRequestException(`Password must be at least ${minLength} characters long`);
    }

    if (!hasUpperCase) {
      throw new BadRequestException('Password must contain at least one uppercase letter');
    }

    if (!hasLowerCase) {
      throw new BadRequestException('Password must contain at least one lowercase letter');
    }

    if (!hasNumbers) {
      throw new BadRequestException('Password must contain at least one number');
    }

    if (!hasSpecialChar) {
      throw new BadRequestException('Password must contain at least one special character');
    }
  }

  private generateTOTPQRCode(email: string, secret: string): string {
    const appName = 'OverseeNOI';
    const otpAuthUrl = `otpauth://totp/${appName}:${email}?secret=${secret}&issuer=${appName}`;
    
    // Generate QR code URL (use a QR code service in production)
    return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpAuthUrl)}`;
  }

  private verifyTOTPToken(secret: string, token: string): boolean {
    // Implement TOTP verification logic
    // This is a simplified version - use a proper TOTP library like 'speakeasy'
    return token.length === 6 && /^\d+$/.test(token);
  }
}

// src/auth/guards/jwt-auth.guard.ts
import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  getRequest(context: ExecutionContext) {
    const ctx = GqlExecutionContext.create(context);
    return ctx.getContext().req;
  }

  handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      throw err || new UnauthorizedException('Token invalid or expired');
    }
    return user;
  }
}

// src/auth/decorators/current-user.decorator.ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';

export const CurrentUser = createParamDecorator(
  (data: unknown, context: ExecutionContext) => {
    const ctx = GqlExecutionContext.create(context);
    return ctx.getContext().req.user;
  },
);

// src/auth/decorators/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const Roles = (...roles: string[]) => SetMetadata('roles', roles);

// =====================================================
// PERFORMANCE OPTIMIZATION & CACHING
// =====================================================

// src/cache/cache.module.ts
import { Module, CacheModule as NestCacheModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as redisStore from 'cache-manager-redis-store';
import { CacheService } from './cache.service';

@Module({
  imports: [
    NestCacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        store: redisStore,
        host: configService.get('REDIS_HOST', 'localhost'),
        port: configService.get('REDIS_PORT', 6379),
        password: configService.get('REDIS_PASSWORD'),
        ttl: configService.get('CACHE_TTL', 300), // 5 minutes default
        max: configService.get('CACHE_MAX_ITEMS', 1000),
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [CacheService],
  exports: [CacheService],
})
export class CacheModule {}

// src/cache/cache.service.ts
import { Injectable, Inject, CACHE_MANAGER } from '@nestjs/common';
import { Cache } from 'cache-manager';

@Injectable()
export class CacheService {
  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  async get<T>(key: string): Promise<T | null> {
    return await this.cacheManager.get<T>(key);
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    await this.cacheManager.set(key, value, ttl);
  }

  async del(key: string): Promise<void> {
    await this.cacheManager.del(key);
  }

  async reset(): Promise<void> {
    await this.cacheManager.reset();
  }

  // Cache key generators
  getUserCacheKey(userId: string): string {
    return `user:${userId}`;
  }

  getPropertyCacheKey(propertyId: string): string {
    return `property:${propertyId}`;
  }

  getRentRollCacheKey(propertyId: string, date: string): string {
    return `rentroll:${propertyId}:${date}`;
  }

  getTasksCacheKey(channelId: string, filters?: any): string {
    const filterHash = filters ? Buffer.from(JSON.stringify(filters)).toString('base64') : 'all';
    return `tasks:${channelId}:${filterHash}`;
  }

  // Batch operations
  async mget<T>(keys: string[]): Promise<(T | null)[]> {
    return Promise.all(keys.map(key => this.get<T>(key)));
  }

  async mset(keyValuePairs: Array<{key: string, value: any, ttl?: number}>): Promise<void> {
    await Promise.all(
      keyValuePairs.map(({ key, value, ttl }) => this.set(key, value, ttl))
    );
  }

  // Pattern-based operations
  async deletePattern(pattern: string): Promise<void> {
    // Note: This requires Redis with SCAN support
    // Implementation would depend on the Redis version and cache-manager version
    console.warn('Pattern deletion not implemented - requires Redis SCAN');
  }
}

// src/cache/decorators/cacheable.decorator.ts
import { SetMetadata } from '@nestjs/common';

export interface CacheableOptions {
  ttl?: number;
  key?: string;
  keyGenerator?: (...args: any[]) => string;
}

export const Cacheable = (options: CacheableOptions = {}) =>
  SetMetadata('cacheable', options);

// src/cache/interceptors/cache.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, of } from 'rxjs';
import { tap } from 'rxjs/operators';
import { CacheService } from '../cache.service';

@Injectable()
export class CacheInterceptor implements NestInterceptor {
  constructor(
    private reflector: Reflector,
    private cacheService: CacheService,
  ) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const cacheableOptions = this.reflector.get('cacheable', context.getHandler());
    
    if (!cacheableOptions) {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest();
    const cacheKey = this.generateCacheKey(context, cacheableOptions, request);
    
    // Try to get from cache
    const cachedResult = await this.cacheService.get(cacheKey);
    if (cachedResult !== null) {
      return of(cachedResult);
    }

    // Execute handler and cache result
    return next.handle().pipe(
      tap(async (result) => {
        if (result !== null && result !== undefined) {
          await this.cacheService.set(cacheKey, result, cacheableOptions.ttl);
        }
      }),
    );
  }

  private generateCacheKey(
    context: ExecutionContext,
    options: any,
    request: any,
  ): string {
    if (options.keyGenerator) {
      return options.keyGenerator(...context.getArgs());
    }

    if (options.key) {
      return options.key;
    }

    // Default key generation
    const className = context.getClass().name;
    const methodName = context.getHandler().name;
    const args = JSON.stringify(context.getArgs());
    const userId = request.user?.id || 'anonymous';
    
    return `${className}:${methodName}:${userId}:${Buffer.from(args).toString('base64').slice(0, 50)}`;
  }
}

// =====================================================
// COMPLETE DEPLOYMENT AUTOMATION
// =====================================================

# scripts/deploy.sh
#!/bin/bash

set -e  # Exit on any error

# Configuration
ENVIRONMENT=${1:-staging}
AWS_REGION=${AWS_REGION:-us-east-1}
ECR_REGISTRY=${ECR_REGISTRY}
CLUSTER_NAME="${ENVIRONMENT}-oversee-cluster"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Validate environment
if [[ "$ENVIRONMENT" != "staging" && "$ENVIRONMENT" != "production" ]]; then
    error "Environment must be 'staging' or 'production'"
    exit 1
fi

# Check required tools
command -v docker >/dev/null 2>&1 || { error "Docker is required but not installed."; exit 1; }
command -v aws >/dev/null 2>&1 || { error "AWS CLI is required but not installed."; exit 1; }
command -v terraform >/dev/null 2>&1 || { error "Terraform is required but not installed."; exit 1; }

log "Starting deployment to ${ENVIRONMENT} environment"

# 1. Build and push Docker images
log "Building Docker images..."

# Get commit SHA for tagging
COMMIT_SHA=$(git rev-parse --short HEAD)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
IMAGE_TAG="${ENVIRONMENT}-${COMMIT_SHA}-${TIMESTAMP}"

# Login to ECR
log "Logging in to ECR..."
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_REGISTRY

# Build frontend
log "Building frontend image..."
docker build -t oversee-noi-frontend:$IMAGE_TAG ./frontend
docker tag oversee-noi-frontend:$IMAGE_TAG $ECR_REGISTRY/oversee-noi-frontend:$IMAGE_TAG
docker tag oversee-noi-frontend:$IMAGE_TAG $ECR_REGISTRY/oversee-noi-frontend:latest-$ENVIRONMENT
docker push $ECR_REGISTRY/oversee-noi-frontend:$IMAGE_TAG
docker push $ECR_REGISTRY/oversee-noi-frontend:latest-$ENVIRONMENT

# Build backend
log "Building backend image..."
docker build -t oversee-noi-backend:$IMAGE_TAG ./backend
docker tag oversee-noi-backend:$IMAGE_TAG $ECR_REGISTRY/oversee-noi-backend:$IMAGE_TAG
docker tag oversee-noi-backend:$IMAGE_TAG $ECR_REGISTRY/oversee-noi-backend:latest-$ENVIRONMENT
docker push $ECR_REGISTRY/oversee-noi-backend:$IMAGE_TAG
docker push $ECR_REGISTRY/oversee-noi-backend:latest-$ENVIRONMENT

success "Docker images built and pushed successfully"

# 2. Deploy infrastructure with Terraform
log "Deploying infrastructure with Terraform..."

cd terraform

# Initialize Terraform
terraform init -reconfigure

# Select workspace
terraform workspace select $ENVIRONMENT || terraform workspace new $ENVIRONMENT

# Plan deployment
log "Planning infrastructure changes..."
terraform plan \
  -var-file="${ENVIRONMENT}.tfvars" \
  -var="frontend_image=$ECR_REGISTRY/oversee-noi-frontend:$IMAGE_TAG" \
  -var="backend_image=$ECR_REGISTRY/oversee-noi-backend:$IMAGE_TAG" \
  -out=tfplan

# Apply changes
if [[ "$ENVIRONMENT" == "production" ]]; then
    warning "Deploying to PRODUCTION. Press Enter to continue or Ctrl+C to abort..."
    read
fi

log "Applying infrastructure changes..."
terraform apply tfplan

# Get outputs
LOAD_BALANCER_DNS=$(terraform output -raw load_balancer_dns_name)
DATABASE_ENDPOINT=$(terraform output -raw database_endpoint)

success "Infrastructure deployed successfully"

cd ..

# 3. Run database migrations
log "Running database migrations..."

# Get database connection details
DB_HOST=$(echo $DATABASE_ENDPOINT | cut -d':' -f1)
DB_PORT=$(echo $DATABASE_ENDPOINT | cut -d':' -f2)

# Run migrations using ECS task
aws ecs run-task \
  --cluster $CLUSTER_NAME \
  --task-definition "${ENVIRONMENT}-oversee-migration" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=DISABLED}" \
  --overrides "{
    \"containerOverrides\": [{
      \"name\": \"migration\",
      \"command\": [\"npm\", \"run\", \"migrate:deploy\"]
    }]
  }"

# Wait for migration to complete
log "Waiting for database migrations to complete..."
sleep 30

# 4. Deploy services
log "Updating ECS services..."

# Update frontend service
aws ecs update-service \
  --cluster $CLUSTER_NAME \
  --service "${ENVIRONMENT}-oversee-frontend" \
  --force-new-deployment

# Update backend service
aws ecs update-service \
  --cluster $CLUSTER_NAME \
  --service "${ENVIRONMENT}-oversee-backend" \
  --force-new-deployment

# Update worker service
aws ecs update-service \
  --cluster $CLUSTER_NAME \
  --service "${ENVIRONMENT}-oversee-worker" \
  --force-new-deployment

# 5. Wait for deployment to stabilize
log "Waiting for services to stabilize..."

aws ecs wait services-stable \
  --cluster $CLUSTER_NAME \
  --services "${ENVIRONMENT}-oversee-frontend" "${ENVIRONMENT}-oversee-backend"

# 6. Run health checks
log "Running health checks..."

# Function to check service health
check_health() {
    local url=$1
    local service_name=$2
    local max_attempts=30
    local attempt=1

    log "Checking health of $service_name at $url"
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$url" > /dev/null; then
            success "$service_name is healthy"
            return 0
        fi
        
        log "Health check attempt $attempt/$max_attempts for $service_name failed, retrying in 10s..."
        sleep 10
        ((attempt++))
    done
    
    error "$service_name health check failed after $max_attempts attempts"
    return 1
}

# Check frontend health
check_health "https://$LOAD_BALANCER_DNS/health" "Frontend"

# Check backend health
check_health "https://$LOAD_BALANCER_DNS/api/health" "Backend"

# 7. Run smoke tests
log "Running smoke tests..."

cd e2e-tests

# Install dependencies if needed
npm ci

# Run smoke tests against the deployed environment
ENVIRONMENT=$ENVIRONMENT \
BASE_URL="https://$LOAD_BALANCER_DNS" \
npm run test:smoke

cd ..

# 8. Update DNS (production only)
if [[ "$ENVIRONMENT" == "production" ]]; then
    log "Updating production DNS..."
    
    # Update Route53 record to point to new load balancer
    aws route53 change-resource-record-sets \
      --hosted-zone-id $HOSTED_ZONE_ID \
      --change-batch "{
        \"Changes\": [{
          \"Action\": \"UPSERT\",
          \"ResourceRecordSet\": {
            \"Name\": \"app.oversee-noi.com\",
            \"Type\": \"CNAME\",
            \"TTL\": 300,
            \"ResourceRecords\": [{\"Value\": \"$LOAD_BALANCER_DNS\"}]
          }
        }]
      }"
fi

# 9. Send deployment notifications
log "Sending deployment notifications..."

# Slack notification
if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
    curl -X POST -H 'Content-type: application/json' \
      --data "{
        \"text\": \":rocket: OverseeNOI deployed to $ENVIRONMENT\",
        \"attachments\": [{
          \"color\": \"good\",
          \"fields\": [
            {\"title\": \"Environment\", \"value\": \"$ENVIRONMENT\", \"short\": true},
            {\"title\": \"Version\", \"value\": \"$IMAGE_TAG\", \"short\": true},
            {\"title\": \"URL\", \"value\": \"https://$LOAD_BALANCER_DNS\", \"short\": false}
          ]
        }]
      }" \
      $SLACK_WEBHOOK_URL
fi

# 10. Clean up old images (keep last 5)
log "Cleaning up old Docker images..."

# Clean up frontend images
aws ecr list-images \
  --repository-name oversee-noi-frontend \
  --filter tagStatus=TAGGED \
  --query 'imageIds[?starts_with(imageTag, `'$ENVIRONMENT'`)][?imageTag != `latest-'$ENVIRONMENT'`]' \
  --output json | \
  jq -r 'sort_by(.imagePushedAt) | reverse | .[5:] | .[] | .imageDigest' | \
  head -20 | \
  xargs -I {} aws ecr batch-delete-image \
    --repository-name oversee-noi-frontend \
    --image-ids imageDigest={}

# Clean up backend images
aws ecr list-images \
  --repository-name oversee-noi-backend \
  --filter tagStatus=TAGGED \
  --query 'imageIds[?starts_with(imageTag, `'$ENVIRONMENT'`)][?imageTag != `latest-'$ENVIRONMENT'`]' \
  --output json | \
  jq -r 'sort_by(.imagePushedAt) | reverse | .[5:] | .[] | .imageDigest' | \
  head -20 | \
  xargs -I {} aws ecr batch-delete-image \
    --repository-name oversee-noi-backend \
    --image-ids imageDigest={}

success "Deployment completed successfully!"
success "Application URL: https://$LOAD_BALANCER_DNS"

log "Deployment summary:"
log "  Environment: $ENVIRONMENT"
log "  Version: $IMAGE_TAG"
log "  Frontend: $ECR_REGISTRY/oversee-noi-frontend:$IMAGE_TAG"
log "  Backend: $ECR_REGISTRY/oversee-noi-backend:$IMAGE_TAG"
log "  Load Balancer: $LOAD_BALANCER_DNS"

# =====================================================
# COMPREHENSIVE TESTING SUITE
# =====================================================

# e2e-tests/smoke.spec.ts
import { test, expect } from '@playwright/test';

test.describe('OverseeNOI Smoke Tests', () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
  const environment = process.env.ENVIRONMENT || 'staging';

  test.beforeAll(async () => {
    console.log(`Running smoke tests against ${environment} environment`);
    console.log(`Base URL: ${baseUrl}`);
  });

  test('application loads successfully', async ({ page }) => {
    await page.goto(baseUrl);
    await expect(page).toHaveTitle(/OverseeNOI/);
  });

  test('health check endpoints respond', async ({ request }) => {
    // Frontend health check
    const frontendHealth = await request.get(`${baseUrl}/health`);
    expect(frontendHealth.status()).toBe(200);

    // Backend health check
    const backendHealth = await request.get(`${baseUrl}/api/health`);
    expect(backendHealth.status()).toBe(200);
    
    const healthData = await backendHealth.json();
    expect(healthData).toHaveProperty('status', 'ok');
    expect(healthData).toHaveProperty('database');
    expect(healthData).toHaveProperty('redis');
  });

  test('authentication flow works', async ({ page }) => {
    await page.goto(`${baseUrl}/login`);
    
    // Use test credentials for staging
    if (environment === 'staging') {
      await page.fill('[data-testid=email-input]', 'test@oversee-noi.com');
      await page.fill('[data-testid=password-input]', 'TestPassword123!');
      await page.click('[data-testid=login-button]');
      
      // Should redirect to dashboard
      await expect(page).toHaveURL(/dashboard/);
      await expect(page.locator('[data-testid=user-menu]')).toBeVisible();
    }
  });

  test('GraphQL API is accessible', async ({ request }) => {
    const graphqlResponse = await request.post(`${baseUrl}/graphql`, {
      data: {
        query: `
          query HealthCheck {
            __typename
          }
        `,
      },
      headers: {
        'Content-Type': 'application/json',
      },
    });

    expect(graphqlResponse.status()).toBe(200);
    const data = await graphqlResponse.json();
    expect(data).toHaveProperty('data');
  });

  test('WebSocket connection works', async ({ page }) => {
    let wsConnected = false;
    
    // Monitor WebSocket connections
    page.on('websocket', ws => {
      ws.on('framesent', event => {
        if (event.payload.includes('connect')) {
          wsConnected = true;
        }
      });
    });

    await page.goto(`${baseUrl}/dashboard`);
    
    // Wait for WebSocket connection
    await page.waitForTimeout(3000);
    
    expect(wsConnected).toBe(true);
  });

  test('error pages are accessible', async ({ page }) => {
    // Test 404 page
    await page.goto(`${baseUrl}/nonexistent-page`);
    await expect(page.locator('text=404')).toBeVisible();
    
    // Test that error page has navigation back to app
    await expect(page.locator('a[href="/dashboard"]')).toBeVisible();
  });

  test('essential static assets load', async ({ page }) => {
    await page.goto(baseUrl);
    
    // Check that CSS is loaded (no FOUC)
    const bodyStyles = await page.locator('body').evaluate(el => 
      getComputedStyle(el).fontFamily
    );
    expect(bodyStyles).not.toBe('');
    
    // Check that favicon loads
    const faviconResponse = await page.request.get(`${baseUrl}/favicon.ico`);
    expect(faviconResponse.status()).toBe(200);
  });

  test('security headers are present', async ({ request }) => {
    const response = await request.get(baseUrl);
    const headers = response.headers();
    
    // Check security headers
    expect(headers).toHaveProperty('strict-transport-security');
    expect(headers).toHaveProperty('x-content-type-options', 'nosniff');
    expect(headers).toHaveProperty('x-frame-options');
    expect(headers).toHaveProperty('x-xss-protection');
  });

  test('database connectivity', async ({ request }) => {
    const healthResponse = await request.get(`${baseUrl}/api/health`);
    const healthData = await healthResponse.json();
    
    expect(healthData.database.status).toBe('connected');
    expect(healthData.database.responseTime).toBeLessThan(1000); // < 1 second
  });

  test('cache system is working', async ({ request }) => {
    const healthResponse = await request.get(`${baseUrl}/api/health`);
    const healthData = await healthResponse.json();
    
    expect(healthData.redis.status).toBe('connected');
    expect(healthData.redis.responseTime).toBeLessThan(100); // < 100ms
  });
});

# =====================================================
# MONITORING AND ALERTING SETUP
# =====================================================

# monitoring/cloudwatch-alarms.tf
resource "aws_cloudwatch_metric_alarm" "high_cpu_frontend" {
  alarm_name          = "${var.environment}-oversee-frontend-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors frontend CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    ServiceName = "${var.environment}-oversee-frontend"
    ClusterName = "${var.environment}-oversee-cluster"
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "high_memory_backend" {
  alarm_name          = "${var.environment}-oversee-backend-high-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors backend memory utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    ServiceName = "${var.environment}-oversee-backend"
    ClusterName = "${var.environment}-oversee-cluster"
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  alarm_name          = "${var.environment}-oversee-database-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "application_errors" {
  alarm_name          = "${var.environment}-oversee-application-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "5XXError"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors application errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
  }

  tags = var.tags
}

# monitoring/custom-metrics.ts
// src/monitoring/metrics.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as AWS from 'aws-sdk';

@Injectable()
export class MetricsService {
  private readonly logger = new Logger(MetricsService.name);
  private cloudWatch: AWS.CloudWatch;

  constructor(private configService: ConfigService) {
    this.cloudWatch = new AWS.CloudWatch({
      region: this.configService.get('AWS_REGION'),
    });
  }

  async recordTaskMetrics(propertyId: string, metrics: any): Promise<void> {
    const params: AWS.CloudWatch.PutMetricDataRequest = {
      Namespace: 'OverseeNOI/Tasks',
      MetricData: [
        {
          MetricName: 'TasksCreated',
          Value: metrics.created,
          Unit: 'Count',
          Dimensions: [
            {
              Name: 'PropertyId',
              Value: propertyId,
            },
          ],
          Timestamp: new Date(),
        },
        {
          MetricName: 'TasksCompleted',
          Value: metrics.completed,
          Unit: 'Count',
          Dimensions: [
            {
              Name: 'PropertyId',
              Value: propertyId,
            },
          ],
          Timestamp: new Date(),
        },
        {
          MetricName: 'AverageResolutionTime',
          Value: metrics.avgResolutionTime,
          Unit: 'Seconds',
          Dimensions: [
            {
              Name: 'PropertyId',
              Value: propertyId,
            },
          ],
          Timestamp: new Date(),
        },
      ],
    };

    try {
      await this.cloudWatch.putMetricData(params).promise();
    } catch (error) {
      this.logger.error('Failed to record task metrics:', error);
    }
  }

  async recordUserActivityMetrics(userId: string, activity: any): Promise<void> {
    const params: AWS.CloudWatch.PutMetricDataRequest = {
      Namespace: 'OverseeNOI/UserActivity',
      MetricData: [
        {
          MetricName: 'UserActions',
          Value: 1,
          Unit: 'Count',
          Dimensions: [
            {
              Name: 'UserId',
              Value: userId,
            },
            {
              Name: 'ActionType',
              Value: activity.type,
            },
          ],
          Timestamp: new Date(),
        },
        {
          MetricName: 'ResponseTime',
          Value: activity.duration,
          Unit: 'Milliseconds',
          Dimensions: [
            {
              Name: 'ActionType',
              Value: activity.type,
            },
          ],
          Timestamp: new Date(),
        },
      ],
    };

    try {
      await this.cloudWatch.putMetricData(params).promise();
    } catch (error) {
      this.logger.error('Failed to record user activity metrics:', error);
    }
  }

  async recordBusinessMetrics(propertyId: string, metrics: any): Promise<void> {
    const params: AWS.CloudWatch.PutMetricDataRequest = {
      Namespace: 'OverseeNOI/Business',
      MetricData: [
        {
          MetricName: 'OccupancyRate',
          Value: metrics.occupancyRate,
          Unit: 'Percent',
          Dimensions: [
            {
              Name: 'PropertyId',
              Value: propertyId,
            },
          ],
          Timestamp: new Date(),
        },
        {
          MetricName: 'DelinquencyRate',
          Value: metrics.delinquencyRate,
          Unit: 'Percent',
          Dimensions: [
            {
              Name: 'PropertyId',
              Value: propertyId,
            },
          ],
          Timestamp: new Date(),
        },
        {
          MetricName: 'MonthlyRevenue',
          Value: metrics.monthlyRevenue,
          Unit: 'Count',
          Dimensions: [
            {
              Name: 'PropertyId',
              Value: propertyId,
            },
          ],
          Timestamp: new Date(),
        },
      ],
    };

    try {
      await this.cloudWatch.putMetricData(params).promise();
    } catch (error) {
      this.logger.error('Failed to record business metrics:', error);
    }
  }
}

# =====================================================
# FINAL SETUP SCRIPT
# =====================================================

# setup.sh
#!/bin/bash

set -e

# OverseeNOI Complete Setup Script
echo "🚀 Setting up OverseeNOI - Super Asset Management Platform"
echo "=================================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root" 
   exit 1
fi

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*)    MACHINE=Cygwin;;
    MINGW*)     MACHINE=MinGw;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo "🖥️  Detected OS: ${MACHINE}"

# Install dependencies based on OS
install_dependencies() {
    echo "📦 Installing dependencies..."
    
    if [[ "$MACHINE" == "Mac" ]]; then
        # macOS
        if ! command -v brew &> /dev/null; then
            echo "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        brew install node yarn docker postgresql redis
        
    elif [[ "$MACHINE" == "Linux" ]]; then
        # Ubuntu/Debian
        sudo apt-get update
        sudo apt-get install -y curl wget gnupg2 software-properties-common
        
        # Node.js
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt-get install -y nodejs
        
        # Yarn
        curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
        echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
        sudo apt-get update && sudo apt-get install -y yarn
        
        # Docker
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        sudo usermod -aG docker $USER
        
        # PostgreSQL and Redis
        sudo apt-get install -y postgresql postgresql-contrib redis-server
    fi
}

# Setup project
setup_project() {
    echo "📁 Setting up project structure..."
    
    # Create necessary directories
    mkdir -p {backend,frontend,extension,mobile,terraform,e2e-tests,docs,scripts}
    
    # Install backend dependencies
    echo "📦 Installing backend dependencies..."
    cd backend
    if [[ ! -f package.json ]]; then
        npm init -y
        npm install @nestjs/core @nestjs/common @nestjs/platform-fastify
        npm install @prisma/client prisma
        npm install @nestjs/jwt @nestjs/passport passport passport-jwt
        npm install @nestjs/graphql @nestjs/apollo graphql apollo-server-fastify
        npm install redis cache-manager cache-manager-redis-store
        npm install aws-sdk sharp tesseract.js
        npm install bcrypt class-validator class-transformer
        npm install --save-dev @types/node typescript ts-node jest
    else
        npm ci
    fi
    cd ..
    
    # Install frontend dependencies
    echo "📦 Installing frontend dependencies..."
    cd frontend
    if [[ ! -f package.json ]]; then
        npx create-next-app@latest . --typescript --tailwind --app --src-dir --import-alias "@/*"
        npm install socket.io-client @apollo/client graphql
        npm install lucide-react recharts
        npm install zustand react-query
    else
        npm ci
    fi
    cd ..
    
    # Install extension dependencies
    echo "📦 Installing extension dependencies..."
    cd extension
    if [[ ! -f package.json ]]; then
        npm init -y
        npm install webpack webpack-cli typescript ts-loader
        npm install --save-dev @types/chrome
    else
        npm ci
    fi
    cd ..
    
    # Install mobile dependencies
    echo "📦 Installing mobile dependencies..."
    cd mobile
    if [[ ! -f package.json ]]; then
        npx react-native init OverseeNOIMobile --template react-native-template-typescript
        cd OverseeNOIMobile
        npm install @react-navigation/native @react-navigation/stack @react-navigation/bottom-tabs
        npm install react-native-screens react-native-safe-area-context
        npm install socket.io-client react-native-push-notification
        npm install @react-native-async-storage/async-storage
        cd ..
    else
        npm ci
    fi
    cd ..
    
    # Install e2e test dependencies
    echo "📦 Installing e2e test dependencies..."
    cd e2e-tests
    if [[ ! -f package.json ]]; then
        npm init -y
        npm install @playwright/test
        npx playwright install
    else
        npm ci
    fi
    cd ..
}

# Setup database
setup_database() {
    echo "🗄️  Setting up database..."
    
    # Start PostgreSQL and Redis
    if [[ "$MACHINE" == "Mac" ]]; then
        brew services start postgresql
        brew services start redis
    elif [[ "$MACHINE" == "Linux" ]]; then
        sudo systemctl start postgresql
        sudo systemctl start redis-server
        sudo systemctl enable postgresql
        sudo systemctl enable redis-server
    fi
    
    # Create database
    sudo -u postgres createdb oversee_dev || true
    sudo -u postgres createdb oversee_test || true
    
    # Create user
    sudo -u postgres psql -c "CREATE USER oversee WITH PASSWORD 'password';" || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE oversee_dev TO oversee;" || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE oversee_test TO oversee;" || true
}

# Setup environment
setup_environment() {
    echo "🔧 Setting up environment..."
    
    # Create .env files
    cat > .env << EOF
# Database
DATABASE_URL="postgresql://oversee:password@localhost:5432/oversee_dev"
TEST_DATABASE_URL="postgresql://oversee:password@localhost:5432/oversee_test"

# Redis
REDIS_URL="redis://localhost:6379"

# JWT
JWT_SECRET="your-super-secret-jwt-key-change-in-production"
JWT_EXPIRES_IN="24h"

# AWS (for production)
AWS_REGION="us-east-1"
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
S3_BUCKET="oversee-noi-files"

# External APIs
OPENAI_API_KEY=""

# Email
SMTP_HOST="smtp.sendgrid.net"
SMTP_PORT="587"
SMTP_USER="apikey"
SMTP_PASS=""

# Push Notifications
VAPID_PUBLIC_KEY=""
VAPID_PRIVATE_KEY=""

# Frontend URLs
FRONTEND_URL="http://localhost:3000"
BACKEND_URL="http://localhost:4000"
EOF

    # Copy to backend
    cp .env backend/.env
    
    # Create frontend .env.local
    cat > frontend/.env.local << EOF
NEXT_PUBLIC_API_URL=http://localhost:4000
NEXT_PUBLIC_WS_URL=ws://localhost:4000
NEXT_PUBLIC_APP_URL=http://localhost:3000
EOF
}

# Setup development tools
setup_dev_tools() {
    echo "🛠️  Setting up development tools..."
    
    # Install global tools
    npm install -g @nestjs/cli prisma nodemon
    
    # Setup Git hooks
    cat > .gitignore << EOF
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Production
build/
dist/
.next/

# Environment
.env
.env.local
.env.production
.env.test

# Database
*.db
*.sqlite

# Logs
logs/
*.log

# Runtime
.pid
.seed
.coverage
.nyc_output

# IDEs
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Terraform
*.tfstate
*.tfstate.*
.terraform/
*.tfplan

# AWS
.aws/

# Cache
.cache/
*.tsbuildinfo
EOF

    # Create package.json for root
    cat > package.json << EOF
{
  "name": "oversee-noi",
  "version": "1.0.0",
  "description": "Super Asset Management Platform",
  "private": true,
  "workspaces": [
    "backend",
    "frontend",
    "extension",
    "mobile",
    "e2e-tests"
  ],
  "scripts": {
    "dev": "docker-compose up -d",
    "dev:logs": "docker-compose logs -f",
    "dev:stop": "docker-compose down",
    "dev:clean": "docker-compose down -v --remove-orphans",
    "test": "npm run test:backend && npm run test:frontend",
    "test:backend": "cd backend && npm test",
    "test:frontend": "cd frontend && npm test",
    "test:e2e": "cd e2e-tests && npm test",
    "build": "npm run build:frontend && npm run build:backend",
    "build:frontend": "cd frontend && npm run build",
    "build:backend": "cd backend && npm run build",
    "lint": "npm run lint:backend && npm run lint:frontend",
    "lint:backend": "cd backend && npm run lint",
    "lint:frontend": "cd frontend && npm run lint",
    "migrate": "cd backend && npx prisma migrate deploy",
    "seed": "cd backend && npm run seed",
    "studio": "cd backend && npx prisma studio",
    "deploy:staging": "bash scripts/deploy.sh staging",
    "deploy:production": "bash scripts/deploy.sh production"
  },
  "keywords": [
    "property-management",
    "asset-management",
    "real-estate",
    "saas"
  ],
  "author": "OverseeNOI Team",
  "license": "UNLICENSED"
}
EOF
}

# Run setup
main() {
    echo "🚀 Starting OverseeNOI setup..."
    
    install_dependencies
    setup_project
    setup_database
    setup_environment
    setup_dev_tools
    
    echo ""
    echo "✅ Setup completed successfully!"
    echo ""
    echo "🔥 Next steps:"
    echo "1. Update .env files with your API keys"
    echo "2. Run 'npm run migrate' to setup database schema"
    echo "3. Run 'npm run seed' to add sample data"
    echo "4. Run 'npm run dev' to start development environment"
    echo "5. Visit http://localhost:3000 to see the application"
    echo ""
    echo "📚 Documentation: ./docs/README.md"
    echo "🐛 Issues: ./docs/TROUBLESHOOTING.md"
    echo ""
    echo "Happy coding! 🎉"
}

# Check if running the script directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi