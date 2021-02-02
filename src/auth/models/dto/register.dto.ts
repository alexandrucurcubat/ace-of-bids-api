import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterDto {
  @IsNotEmpty()
  @IsEmail()
  @ApiProperty({ required: true })
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  @ApiProperty({ required: true, minLength: 3 })
  username: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @ApiProperty({ required: true, minLength: 6 })
  password: string;
}
