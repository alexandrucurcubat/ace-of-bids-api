import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { Observable } from 'rxjs';

import { AuthService } from '../services/auth.service';
import { RegisterDto } from '../models/dto/register.dto';
import { LoginDto } from '../models/dto/login.dto';
import { IUser } from 'src/user/models/user.interface';
import { IJwt } from '../models/jwt.interface';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(201)
  register(@Body() registerDto: RegisterDto): Observable<IUser> {
    return this.authService.register(registerDto);
  }

  @Post('login')
  @HttpCode(200)
  login(@Body() loginDto: LoginDto): Observable<IJwt> {
    return this.authService.login(loginDto);
  }
}
