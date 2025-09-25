import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthService } from '../services/auth.service';
import { ROLES_TOKEN, TOKEN_FROM, TokenSource } from '../decorators';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    // Extract token
    const tokenSource: TokenSource =
      this.reflector.getAllAndOverride(TOKEN_FROM, [
        context.getHandler(),
        context.getClass(),
      ]) || 'header';

    let token: string | undefined;

    if (tokenSource === 'header') {
      const auth = request.headers['authorization'] as string | undefined;
      if (auth?.startsWith('Bearer '))
        token = auth.slice('Bearer '.length).trim();
    } else if (tokenSource === 'query') {
      token = request.query['auth'] as string | undefined;
    }

    if (!token) throw new UnauthorizedException('Missing token');

    // Verify token and attach user
    let user;
    try {
      const payload = await this.authService.verifyToken(token);
      user = await this.authService.validate(payload);
      request.user = user;
    } catch (err) {
      throw new UnauthorizedException(`Invalid token: ${String(err)}`);
    }

    // Enforce roles
    const requiredRoles: string[] =
      this.reflector.getAllAndOverride<string[]>(ROLES_TOKEN, [
        context.getHandler(),
        context.getClass(),
      ]) || [];

    if (requiredRoles.length > 0) {
      const hasRole = requiredRoles.some((role) => user.roles?.includes(role));
      if (!hasRole) throw new ForbiddenException('Insufficient role');
    }

    return true;
  }
}
