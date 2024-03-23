import { ApiProperty } from "@nestjs/swagger";

export class VerificationCodeDto {
    @ApiProperty()
    email: string;
    @ApiProperty()
    code: string;
}