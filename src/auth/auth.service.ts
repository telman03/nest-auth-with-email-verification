import { Injectable, BadRequestException, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { PrismaClient, UserRole } from '@prisma/client';
import { PrismaService } from 'prisma/prisma.service';
import { JwtStrategy } from './jwt.strategy';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/signup.dto';
import { jwtSecret } from 'src/utils/constants';
import * as bcrypt from 'bcrypt';
import { SignInDto } from './dto/signin.dto';
import { Request, Response } from 'express';
import { Resend } from 'resend';


const resend = new Resend('re_9wgbAAvU_AHmZVLJQ4gs2xQG3bnJMGv8y');


@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
   ) {}

  async signUp(dto: SignUpDto) {
    const { email, password, firstName, lastName, role } = dto;

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString(); // Genarate the OTP code

    const userExists = await this.prisma.user.findUnique({
      where: { email },
    });

    if (userExists) {
      throw new BadRequestException('Email already exists');
    }

     // Save OTP to database
    await this.prisma.otp.create({
      data: {
        email,
        code: otpCode,
      },
    });

    const hashedPassword = await this.hashPassword(password);
    const newUser = await this.prisma.user.create({
      data: {
        email,
        firstName,
        lastName,
        role: UserRole.USER,
        hashedPassword,
      },
    });
    // Send OTP via email
    const { data, error } = await resend.emails.send({
      from: 'Nest Auth <info@telmangadimov.site>', //CHECK LATER
      to: [email],
      subject: 'Email Verification',
      html: `<p>Your verification code is: <strong>${otpCode}</strong></p>`,
    });
    if (error) {
      throw new ForbiddenException('Failed to send verification email');
    }
    return {
      message: 'User created succefully', user: {
        id: newUser.id,
        email: newUser.email,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        role: newUser.role,
      },
    };
  }

  async signin(dto: SignInDto, req: Request, res: Response) {
    const { email, password } = dto;

    const foundUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!foundUser) {
      throw new BadRequestException('Wrong credentials');
    }

    const compareSuccess = await this.comparePasswords({
      password,
      hash: foundUser.hashedPassword,
    });

    if (!compareSuccess) {
      throw new BadRequestException('Wrong credentials');
    }

    const token = await this.signToken({
      userId: foundUser.id,
      email: foundUser.email,
      firstName: foundUser.firstName,
      lastName: foundUser.lastName,
      role: foundUser.role
    });

    if (!token) {
      throw new ForbiddenException('Could not signin');
    }

    res.cookie('token', token, { httpOnly: true, secure: true }); // secure: true in production
    // console.log(token);

    return res.send({
      message: 'Logged in successfully',
      user: {
        id: foundUser.id,
        email: foundUser.email,
        firstName: foundUser.firstName,
        lastName: foundUser.lastName,
        role: foundUser.role,
      },
    });
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('token');

    return res.send({ message: 'Logged out succefully' });
  }

  async signToken(args: { userId: string; email: string, firstName: string, lastName: string, role: string }) {
    const payload = {
      id: args.userId,
      email: args.email,
      firstName: args.firstName,
      lastName: args.lastName,
      role: args.role
    };

    const token = await this.jwt.signAsync(payload, {
      secret: jwtSecret,
    });

    return token;
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;

    return await bcrypt.hash(password, saltOrRounds);
  }
  async comparePasswords(args: { hash: string; password: string }) {
    return await bcrypt.compare(args.password, args.hash);
  }

  async getCurrentUser(token: string): Promise<any> {
    try {
      const decodedToken = this.jwt.verify(token, { secret: jwtSecret });

      const { id, email, firstName, lastName, role } = decodedToken;

      return { id, email, firstName, lastName, role };
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
  private generateOTP(): string {
    // Generate a random 6-digit OTP code
    return Math.floor(100000 + Math.random() * 900000).toString();
  }
}
