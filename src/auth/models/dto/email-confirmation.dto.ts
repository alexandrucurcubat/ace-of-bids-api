import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class EmailConfirmationDto {
  @IsNotEmpty()
  @IsEmail()
  @ApiProperty({ required: true })
  email: string;
}
