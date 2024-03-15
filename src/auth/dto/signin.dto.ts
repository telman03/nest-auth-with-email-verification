import { ApiProperty } from '@nestjs/swagger';
import { User, UserRole } from '@prisma/client';
import { IsNotEmpty, IsString, IsEmail, Length, IsEnum } from 'class-validator';


export class SignInDto {
    @IsNotEmpty()
    @ApiProperty()
    @IsString()
    @IsEmail()
    public email: string;
  
    @IsNotEmpty()
    @IsString()
    @ApiProperty()
    @Length(3, 20, { message: 'Passowrd has to be at between 3 and 20 chars' })
    public password: string;
}