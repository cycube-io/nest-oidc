import { Injectable, ExecutionContext } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';

let graphql: {
  GqlExecutionContext: { create: (ec: ExecutionContext) => any };
};
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  graphql = require('@nestjs/graphql');
} catch (e) {}

@Injectable()
export class JwtAuthGuardGraphQL extends JwtAuthGuard {
  getRequest(context: ExecutionContext) {
    const ctx = graphql.GqlExecutionContext.create(context);
    return ctx.getContext().req;
  }
}
