import { SignUpDto } from './dto/signup.dto';
import { Body, Controller, Get, Post, Request, Response , Req} from '@nestjs/common';
import { AuthService } from './auth.service';
import {  BadRequestException,UnauthorizedException,UseGuards } from '@nestjs/common';
import { SignInDto } from './dto/signin.dto';
import { Request as ExpressRequest } from 'express';

import { HttpOnlyGuard } from './http-only.guard';
import { ApiCookieAuth, ApiTags } from '@nestjs/swagger';
import { JwtService } from '@nestjs/jwt';
import { VerificationCodeDto } from './dto/verify-user.dto';

@Controller('auth')
@ApiTags('auth')

export class AuthController {
    constructor(private authService: AuthService, private jwtService: JwtService) {}


    @Post('signup')
    signup(@Body() dto: SignUpDto) {
      return this.authService.signUp(dto);
    }

    @Post('signin')
    async signin(@Request() req, @Response() res, @Body() dto: SignInDto) {
      return this.authService.signin(dto, req, res);
    }

    @Get('signout')
    signout(@Request() req, @Response() res) {
      return this.authService.signout(req, res);
    }

    @Get('profile')
    @UseGuards(HttpOnlyGuard)
    @ApiCookieAuth()
    async getProfile(@Req() req: ExpressRequest) {
      const token = req.cookies.token;
    
      if (!token) {
        throw new UnauthorizedException('Token not provided');
      }
    
      const user = await this.authService.getCurrentUser(token);
    
      return {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      };
    }

    @Post('verify')
    async verifyCode(@Body() dto: VerificationCodeDto): Promise<any> {
      const { email, code } = dto;

      if (!email || !code) {
        throw new BadRequestException('Email and code are required');
      }
  
      const isValid = await this.authService.verifyUser(dto);
  
      if (!isValid) {
        throw new BadRequestException('Invalid verification code');
      }

      await this.authService.markUserAsVerified(email)
      return { message: 'Verification successful' };
    
    }
  
}
