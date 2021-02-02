import { IsNotEmpty, IsOptional, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateUserDto {
  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  @ApiProperty({ required: true, minLength: 3 })
  username: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty({ required: true, minLength: 6 })
  oldPassword: string;

  @IsOptional()
  @IsString()
  @MinLength(6)
  @ApiProperty({ required: true, minLength: 6 })
  newPassword: string;
}
