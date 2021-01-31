import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  UseGuards,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import ms = require('ms');

import { IUser } from '../models/user.interface';
import { UserService } from '../services/user.service';
import { CreateUserDto } from '../models/dto/create-user.dto';
import { LoginUserDto } from '../models/dto/login-user.dto';
import { map } from 'rxjs/operators';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { IAuthResponse } from '../models/auth-response.interface';

@Controller('users')
export class UserController {
  constructor(private userService: UserService) {}

  @Post('register')
  @HttpCode(201)
  create(@Body() createUserDto: CreateUserDto): Observable<IUser> {
    return this.userService.create(createUserDto);
  }

  @Post('login')
  @HttpCode(200)
  login(@Body() loginUserDto: LoginUserDto): Observable<IAuthResponse> {
    return this.userService.login(loginUserDto).pipe(
      map(
        (token: string): IAuthResponse => {
          return {
            token,
            expiresIn: ms(process.env.JWT_EXPIRES_IN) / 1000,
          };
        },
      ),
    );
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  @HttpCode(200)
  // @HasRoles('admin')
  findAll(): Observable<IUser[]> {
    return this.userService.findAll();
  }
}
