# NestJS OIDC

A configurable OIDC library for NestJS and REST.

This package is a fork of [@5stones/nest-oidc](https://github.com/5-stones/nest-oidc) by Jacob Spizziri. Unlike the original, this fork removes the use of `@nestjs/passport` and `jsonwebtoken`, replacing them with `jose` to enable caching and support efficient algorithms such as Ed25519. It also omits GraphQL support for simplicity. If you need GraphQL support, please use the original package instead.


- [Install](#install)
- [Basic Setup & Usage](#basic-setup--usage)
- [Guards](#guards)
  - [REST](#rest-guard)
- [Current User](#current-user)
  - [REST](#rest-user)
- [Roles](#roles)
- [Role Evaluators](#role-evaluators)
- [JWT Mapping](#jwt-mapping)
- [Multiple Realms](#multiple-realms)
- [Advanced](#advanced)
  - [Token From Query](#token-from-query)
  - [Optional Authentication](#optional-authentication)
- [Release](#release)
- [Credits](#credits)

## Install

Install `nest-oidc`:

```sh
npm i @cycube/nest-oidc
```


## Basic Setup & Usage

You'll need to import and configure the `AuthModule` in your application. This
package contains a JWT authentication guard which will validate a JWT against
the issuer's public key. You must pass configure a value either for the `oidcAuthority` or a `realms` array with at least one realm (see [Multiple Realms](#multiple-realms)).

```ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@cycube/nest-oidc';

@Module({
  imports: [
    ...
    AuthModule.forRoot({
      oidcAuthority: 'http://iam.app.com/auth/realms/app',
    }),
  ],
})
export class AppModule {}
```

This will add the JWT validation guard, and will verify any incoming JWT's
against the OIDC authorities public keys.

Finally, you should decorate your endpoints with the provided guards.

## Guards

This package exports a basic guard:

- `JwtAuthGuard` - for use in REST contexts.

#### REST Guard

Applying the guard will require a valid JWT to be passed in order to access any
of the controller endpoints:

```ts
import { Controller, Get, UseGuards } from '@nestjs/common';
import { Roles, JwtAuthGuard } from '@cycube/nest-oidc';

@UseGuards(JwtAuthGuard)
@Controller('cats')
export class CatsController {
  @Get()
  findAll(): string {
    return 'This action returns all cats';
  }
}
```

You can also use it on specific endpoints:

```ts
import { Controller, Get, Post, UseGuards } from '@nestjs/common';
import { Roles, JwtAuthGuard } from '@cycube/nest-oidc';

@Controller('cats')
export class CatsController {
  @UseGuards(JwtAuthGuard)
  @Post()
  create(): string {
    return 'This action adds a new cat';
  }

  @Get()
  findAll(): string {
    return 'This action returns all cats';
  }
}
```

## Current User

This package exports a basic user decorator:

- `CurrentUser` - for use in REST contexts.

#### REST User

```ts
import { Controller, Get, UseGuards } from '@nestjs/common';
import { Roles, JwtAuthGuard, CurrentUser } from '@cycube/nest-oidc';

@UseGuards(JwtAuthGuard)
@Controller('cats')
export class CatsController {
  @Get()
  findAll(@CurrentUser() user: any): string {
    return 'This action returns all cats';
  }
}
```


## Roles

If you want to permission different endpoints based on properties of the JWT you
can do so using the `Roles` decorator in conjunction with the Auth Guard. The `Roles` decorator will accept a list of `string`s and will
check if the user object accessing that endpoint has any of those strings in the
`user.roles` property. It expects the `user.roles` property to be a flat array
of strings.

#### Example

```ts
import { Controller, Get, UseGuards } from '@nestjs/common';
import { Roles, JwtAuthGuard } from '@cycube/nest-oidc';

@UseGuards(JwtAuthGuard)
@Controller('cats')
export class CatsController {
  @Get()
  findAll(): string {
    return 'This action returns all cats';
  }

  @Roles('ADMIN', 'SUPER_ADMIN')
  @Delete()
  findAll(id: string): string {
    return 'This action deletes a cat';
  }
}
```

In this scenario, the deletion can only be executed by an `ADMIN` or `SUPER_ADMIN`
but the query can be executed by any user with a valid JWT.

:warning: Note: if you do not pass _any_ roles parameters to the `Roles`
decorator (i.e. `@Roles()`) it is the same as not adding the decorator at all.

## Role Evaluators

If your JWT doesn't natively have a `.roles` property of strings on it, you can
use evaluators to map properties of the JWT to a role. You can do so by
configuring `roleEvaluators`. `roleEvaluators` are an array of
`RoleEvaluator` objects which consist of an `expression`, and the access `role`
that that particular expression grants upon evaluating to `true`.

An `expression` can be any valid [`jexl`](https://www.npmjs.com/package/jexl)
expression.

#### Example

Suppose you have a JWT with the following structure:

```ts
{
  roles: [
     { name: "SUPER_USER", id: 1 },
     ...
     { name: "PREMIUM", id: 2 },
  ],
}
```

You could then configure an evaluator like the following, which would map a
user that has a `role` of with the name of `SUPER_USER` to the `ADMIN`
role in your application.

```ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@cycube/nest-oidc';

@Module({
  imports: [
    ...
    AuthModule.forRoot({
      oidcAuthority: 'http://iam.app.com/auth/realms/app',
      roleEvaluators: [
        {
          expression: 'jwt.roles[.name == "SUPER_USER"]|length > 0',
          role: 'ADMIN',
        },
      ],
    }),
  ],
})
export class AppModule {}
```

The user object within your application will now have the following:

```ts
{
  ...
  roles: [
    "ADMIN",
  ],
}
```

Then you would simply decorate your endpoint with the `@Roles('ADMIN')`
annotation in order to lock it down to users of that role.

## JWT Mapper

By default, the JWT payload is passed as the user into the application. However,
if you need to map the JWT payload to different structure you can pass the
`jwtMapper` option:

```ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@cycube/nest-oidc';

@Module({
  imports: [
    ...
    AuthModule.forRoot({
      oidcAuthority: 'http://iam.app.com/auth/realms/app',
      jwtMapper: async (payload: any) => ({
        id: payload.sub,
        email: payload.email,
        ...
      }),
    }),
  ],
})
export class AppModule {}
```


## Multiple Realms

You can use multiple realms (or multiple issuers) by configuring the `AuthModule` with the `realms` array:

```ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@cycube/nest-oidc';

@Module({
  imports: [
    ...
    AuthModule.forRoot({
      realms: [
        {
          realm: 'one',
          oidcAuthority: 'http://iam.app.com/auth/realms/one',
        }, {
          realm: 'two',
          oidcAuthority: 'http://iam.app.com/auth/realms/two',
        }, {
          realm: 'three',
          oidcAuthority: 'http://iam.anotherapp.com/auth/realms/three',
          jwtMapper: ... ,      // specific, for this realm only
          roleEvaluators: ... , // specific, for this realm only
        }
      ],
      jwtMapper: ... ,      // global for all realms
      roleEvaluators: ... , // global for all realms
    }),
  ],
})
export class AppModule {}
```

Some notes about multi-realm configurations:

1. This feature relies on the `iss` (issuer) field of generated JWT tokens. Each realm must have a unique `iss` string that maps to the `oidcAuthority` of the realm for this to work. It was tested against Keycloak v26.3.4 but is expected to work with other OIDC providers.

2. A custom `jwtMapper` can be set either globally or per-realm. Realms with no `jwtMapper` will inherit the value from the global one.

3. Same rule applies for `roleEvaluators`.

4. When registering `AuthModule`, if a `realms` array is provided, the global `oidcAuthority` is redundant and ignored.



## Advanced

#### Token From Query

By default, the JWT token is extracted from the `authorization` request header. In some cases, like a short-lived URL for an external user, you may want to construct a URL which contains a JWT token in the request query string:

https://my-api/cats/show?auth=eyJhbGc...

This can be done for either a single endpoint or an entire controller using the `@TokenFrom` decorator:

```ts
import { Controller, Get, UseGuards } from '@nestjs/common';
import { Roles, JwtAuthGuard, TokenFrom } from '@cycube/nest-oidc';

@Controller('cats')
@UseGuards(JwtAuthGuard)
export class CatsController {
  @TokenFrom('query')
  @Roles('EXTERNAL_USER')
  @Get('/show')
  showCat(): string {
    return 'This action shows a specific cat';
  }
}
```

#### Optional Authentication

You can use the `IsAuthenticationOptional` decorator on an endpoint or resolver
in conjunction with an auth guard. If this is done so, then JWTs will populate
`user` object as expected. If an invalid JWT is passed or no JWT is passed at
all, then no user will be populated on the request.

## Release

The standard release command for this project is:
```
npm version [<newversion> | major | minor | patch | premajor | preminor | prepatch | prerelease | from-git]
```

This command will:

1. Generate/update the Changelog
1. Bump the package version
1. Tag & pushing the commit


e.g.

```
npm version 1.2.17
npm version patch // 1.2.17 -> 1.2.18
```

## Credits
- Original work by [Jacob Spizziri](https://github.com/jspizziri).
- Maintained fork by [Oren Chapo](https://github.com/OrenChapo).
