import {
  Body,
  Controller,
  HttpCode,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth } from '@nestjs/swagger';

import { AuthService } from '../services/auth.service';
import { RegisterDto } from '../models/dto/register.dto';
import { LoginDto } from '../models/dto/login.dto';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { IsOwnerGuard } from '../guards/is-owner.guard';
import { UpdateUsernameDto } from 'src/auth/models/dto/update-username.dto';
import { UpdatePasswordDto } from 'src/auth/models/dto/update-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(201)
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  @HttpCode(200)
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @UseGuards(JwtAuthGuard, IsOwnerGuard)
  @Post('update/username/:id')
  @HttpCode(200)
  @ApiBearerAuth()
  updateUsername(
    @Param('id') id: number,
    @Body() updateUsernameDto: UpdateUsernameDto,
  ) {
    return this.authService.updateUsername(id, updateUsernameDto);
  }

  @UseGuards(JwtAuthGuard, IsOwnerGuard)
  @Post('update/password/:id')
  @HttpCode(200)
  @ApiBearerAuth()
  updatePassword(
    @Param('id') id: number,
    @Body() updatePasswordDto: UpdatePasswordDto,
  ) {
    return this.authService.updatePassword(id, updatePasswordDto);
  }
}
