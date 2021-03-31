import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Redirect,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth } from '@nestjs/swagger';

import { AuthService } from '../services/auth.service';
import { RegisterDto } from '../models/dto/register.dto';
import { LoginDto } from '../models/dto/login.dto';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { ParamGuard } from '../guards/param.guard';
import { UpdateUsernameDto } from 'src/auth/models/dto/update-username.dto';
import { UpdatePasswordDto } from 'src/auth/models/dto/update-password.dto';
import { EmailConfirmationDto } from '../models/dto/email-confirmation.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(201)
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('confirmation/resend')
  @HttpCode(200)
  resendConfirmation(@Body() emailConfirmationDto: EmailConfirmationDto) {
    return this.authService.resendConfirmation(emailConfirmationDto);
  }

  @Get('confirmation/:jwt')
  @HttpCode(200)
  @Redirect(process.env.CLIENT_URL)
  confirm(@Param('jwt') jwt: string) {
    return this.authService.confirmEmail(jwt);
  }

  @Post('login')
  @HttpCode(200)
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @UseGuards(JwtAuthGuard, ParamGuard)
  @Post('update/username/:id')
  @HttpCode(200)
  @ApiBearerAuth()
  updateUsername(
    @Param('id') id: number,
    @Body() updateUsernameDto: UpdateUsernameDto,
  ) {
    return this.authService.updateUsername(id, updateUsernameDto);
  }

  @UseGuards(JwtAuthGuard, ParamGuard)
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
