import { SetMetadata } from '@nestjs/common';

export const TOKEN_FROM = 'token_from';

export type TokenSource = 'header' | 'query';

export const TokenFrom = (source: TokenSource) =>
  SetMetadata(TOKEN_FROM, source);
