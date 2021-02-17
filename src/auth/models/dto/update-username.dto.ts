import { IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateUsernameDto {
  @IsNotEmpty()
  @IsString()
  @ApiProperty({ required: true })
  oldPassword: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  @ApiProperty({ required: true, minLength: 3 })
  username: string;
}
