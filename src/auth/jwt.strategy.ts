import { Strategy, ExtractJwt } from "passport-jwt";
import {PassportStrategy} from '@nestjs/passport';
import { Injectable,  } from '@nestjs/common';
import { Request } from 'express';
import { UUID } from "crypto";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor() {
        super({
          jwtFromRequest: ExtractJwt.fromExtractors([
            JwtStrategy.extractJWT,
            ExtractJwt.fromAuthHeaderAsBearerToken(),
          ]),
          secretOrKey: process.env.JWT_SECRET,
        });
      }
      private static extractJWT(req: Request): string | null {
        if (req.cookies && 'token' in req.cookies) {
          return req.cookies.token;
        }
        return null;
      }
    
      async validate(payload: { id: string; email: string, firstName: string, lastName: string,role: string }) {
        return payload;
      }

}
