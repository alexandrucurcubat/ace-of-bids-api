import { IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

import { LoginUserDto } from './login-user.dto';

export class CreateUserDto extends LoginUserDto {
  @ApiProperty({ required: true, minLength: 3 })
  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  username: string;
}
