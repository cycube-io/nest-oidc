import { Module, DynamicModule } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';

import { JWT_MAPPER, OIDC_AUTHORITY, ROLE_EVALUATORS, REALMS } from './consts';
import { RoleEvaluator } from './interfaces';
import { AuthService } from './services';

export interface AuthModuleRealmOptions {
  realm: string;
  oidcAuthority: string;
  roleEvaluators?: RoleEvaluator[];
  jwtMapper?: (payload: any) => any;
}

export interface AuthModuleRegistrationOptions {
  oidcAuthority?: string;
  roleEvaluators?: RoleEvaluator[];
  jwtMapper?: (payload: any) => any;
  realms?: AuthModuleRealmOptions[];
}

@Module({})
export class AuthModule {
  static forRoot(options: AuthModuleRegistrationOptions): DynamicModule {
    return {
      module: AuthModule,
      imports: [HttpModule],
      providers: [
        AuthService,
        {
          provide: OIDC_AUTHORITY,
          useValue: options.oidcAuthority,
        },
        {
          provide: ROLE_EVALUATORS,
          useValue: options.roleEvaluators || [],
        },
        {
          provide: JWT_MAPPER,
          useValue: options.jwtMapper
            ? options.jwtMapper
            : (payload: any) => payload,
        },
        {
          provide: REALMS,
          useValue: options.realms || [],
        },
      ],
      exports: [AuthService],
    };
  }
}
