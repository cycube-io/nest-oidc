import {
  Injectable,
  Inject,
  OnModuleInit,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { lastValueFrom } from 'rxjs';
import { JWT_MAPPER, OIDC_AUTHORITY, REALMS, ROLE_EVALUATORS } from '../consts';
import { RoleEvaluator } from '../interfaces';
import jexl from 'jexl';
import {
  createRemoteJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  JWTPayload,
  jwtVerify,
} from 'jose';
import { AuthModuleRealmOptions } from '../auth.module';

const DEFAULT_REALM = 'default';

const length = (elem: any) => (elem ? elem.length : 0);
const mapValue = (obj: any) =>
  obj ? obj.map((value: any) => ({ value })) : [];

jexl.addTransform('length', length);
jexl.addTransform('mapValue', mapValue);

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);
  private readonly _realms: Record<
    string,
    {
      realm: string;
      oidcConfig: Promise<any> | undefined;
      jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
      evaluators: RoleEvaluator[];
      jwtMapper: (payload: any) => any;
    }
  > = {};

  constructor(
    @Inject(ROLE_EVALUATORS)
    protected readonly evaluators: RoleEvaluator[],
    @Inject(OIDC_AUTHORITY)
    protected readonly oidcAuthority: string,
    @Inject(JWT_MAPPER)
    protected readonly jwtMapper: (payload: any) => any,
    @Inject(REALMS)
    protected readonly realms: AuthModuleRealmOptions[],
    protected readonly httpService: HttpService,
  ) {
    if (realms?.length) {
      // multiple realms
      realms.forEach((r) => {
        if (!r.oidcAuthority) {
          this.logger.warn(
            `Skipping realm "${r.realm}" with invalid oidcAuthority`,
          );
          return;
        }
        this._realms[r.oidcAuthority] = {
          realm: r.realm,
          jwks: undefined,
          oidcConfig: undefined,
          evaluators: r.roleEvaluators || evaluators,
          jwtMapper: r.jwtMapper || jwtMapper,
        };
      });
    } else if (oidcAuthority) {
      // single realm
      this._realms[oidcAuthority] = {
        realm: DEFAULT_REALM,
        jwks: undefined,
        oidcConfig: undefined,
        evaluators,
        jwtMapper,
      };
    } else {
      const errTxt = `Either "realms" or "oidcAuthority" must be specified.`;
      this.logger.error(errTxt);
      throw new Error(errTxt);
    }
  }

  onModuleInit() {
    // attempt to eagerly load JWKS
    Object.keys(this._realms).forEach((k) => {
      this.getJwks(k).catch((err) => {
        this.logger.warn(
          `Failed to load JWKS for realm "${this._realms[k].realm}" on init: ${err}`,
        );
      });
    });
  }

  private async getJwks(oidcAuthority: string) {
    if (!this._realms[oidcAuthority].jwks) {
      const { jwks_uri } = await this.oidcConfig(oidcAuthority);
      // createRemoteJWKSet will fetch keys and cache them internally
      this._realms[oidcAuthority].jwks = createRemoteJWKSet(new URL(jwks_uri));
    }
    return this._realms[oidcAuthority].jwks;
  }

  async oidcConfig(oidcAuthority: string): Promise<any> {
    if (!oidcAuthority || !this._realms[oidcAuthority]) {
      throw new Error(`Invalid issuer "${oidcAuthority}"`);
    }
    if (!this._realms[oidcAuthority].oidcConfig) {
      this._realms[oidcAuthority].oidcConfig = this.loadOidcConfig(
        oidcAuthority,
      ).catch((err) => {
        // allow retry by clearing cached promise
        this._realms[oidcAuthority].oidcConfig = undefined;
        throw err;
      });
    }
    return await this._realms[oidcAuthority].oidcConfig;
  }

  /**
   * Verify the JWT using jose and the realm JWKS.
   * Returns the verified payload (throws on error).
   *
   * @param rawJwtToken raw token string
   * @param opts optional verify options: audience override
   */
  async verifyToken(
    rawJwtToken: string,
    opts?: { audience?: string | string[] },
  ): Promise<JWTPayload> {
    try {
      // get issuer from JWT token
      const issuer = decodeJwt(rawJwtToken)?.iss;
      if (!issuer) {
        throw new Error(`Unrecognized issuer`);
      }
      // decode header for logging/debugging (kid/alg)
      const header = decodeProtectedHeader(rawJwtToken);
      this.logger.debug(
        `Verifying token with alg=${header.alg} kid=${header.kid} issuer=${issuer}`,
      );

      const jwks = await this.getJwks(issuer);

      const verifyOptions: any = { issuer };
      if (opts?.audience) verifyOptions.audience = opts.audience;

      const { payload } = await jwtVerify(rawJwtToken, jwks, verifyOptions);
      return payload as JWTPayload;
    } catch (err) {
      this.logger.error(`Token verification failed: ${String(err)}`);
      throw err;
    }
  }

  /**
   * Legacy compatibility: keep a keyProvider getter only if some other
   * code expects SecretOrKeyProvider. NOTE: This will NOT enable EdDSA
   * because passport-jwt/jsonwebtoken cannot verify EdDSA. Prefer using
   * verifyToken() + custom strategy (see jwt.strategy.ts).
   */
  get keyProvider() {
    // keep stub for compatibility; it will error for EdDSA tokens
    return (_request: any, _rawJwtToken: string, done: any) => {
      done(
        new Error(
          'keyProvider is deprecated in this fork. Use AuthService.verifyToken() instead.',
        ),
        false,
      );
    };
  }

  async validate(payload: JWTPayload): Promise<any> {
    if (!payload.iss) {
      throw new Error(`Invalid issuer`);
    }
    const cfg = this._realms[payload.iss];
    if (!cfg) {
      throw new Error(`Unrecognized issuer`);
    }
    const user: any = cfg.jwtMapper(payload);

    if (cfg.evaluators?.length) {
      const roles: string[] = [];

      for (const evaluator of cfg.evaluators) {
        try {
          let hasRole = await jexl.eval(evaluator.expression, { jwt: payload });
          hasRole = !!hasRole; // explicitly cast to boolean

          if (hasRole) {
            roles.push(evaluator.role);
          }
        } catch {
          throw new Error(`Error evaluating JWT role '${evaluator.role}'.`);
        }
      }

      user.roles = roles;
    }

    return user;
  }

  private async loadOidcConfig(oidcAuthority: string): Promise<any> {
    try {
      const source$ = this.httpService.get(
        `${oidcAuthority}/.well-known/openid-configuration`,
      );
      const response = await lastValueFrom(source$);
      this.logger.debug(`Loaded OIDC config for authority: ${oidcAuthority}`);
      return response.data;
    } catch (err) {
      // this only bubbles up to init logs or callers
      throw new ServiceUnavailableException(
        `Failed to fetch openid-configuration for "${oidcAuthority}": ${err}`,
        { cause: err as Error },
      );
    }
  }
}
