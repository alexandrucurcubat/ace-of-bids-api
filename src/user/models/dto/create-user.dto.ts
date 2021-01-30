import { IsNotEmpty, IsString, MinLength } from 'class-validator';

import { LoginUserDto } from './login-user.dto';

export class CreateUserDto extends LoginUserDto {
  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  username: string;
}
