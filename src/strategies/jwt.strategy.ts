// jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { Request } from 'express';
import { AuthService } from '../services/auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly authService: AuthService) {
    super();
  }

  /**
   * Passport-custom will call this validate with the request.
   * We extract the Bearer token, call authService.verifyToken(),
   * then call authService.validate() (role mapping), and return the user.
   *
   * Returning the user attaches it to req.user for Nest guards.
   */
  async validate(req: Request): Promise<any> {
    const auth = req.headers['authorization'] as string | undefined;
    if (!auth || !auth.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing Authorization header');
    }

    const token = auth.slice('Bearer '.length).trim();
    if (!token) throw new UnauthorizedException('Empty Bearer token');

    try {
      // verify (supports EdDSA, ES256, RS256, etc.)
      const payload = await this.authService.verifyToken(token);

      // convert payload -> user object + roles via existing validate()
      const user = await this.authService.validate(payload);
      return user;
    } catch (err) {
      // err may be from jose jwtVerify (signature, exp, kid mismatch, etc.)
      throw new UnauthorizedException(`Invalid token: ${String(err)}`);
    }
  }
}
