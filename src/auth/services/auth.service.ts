import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { from, Observable, throwError } from 'rxjs';
import * as bcrypt from 'bcrypt';

import { IUser } from 'src/user/models/user.interface';
import { UserEntity } from 'src/user/models/user.entity';
import { RegisterDto } from '../models/dto/register.dto';
import { catchError, map, switchMap } from 'rxjs/operators';
import { LoginDto } from '../models/dto/login.dto';
import { IJwt } from '../models/jwt.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    private jwtService: JwtService,
  ) {}

  register(registerDto: RegisterDto): Observable<IUser> {
    return this.emailExists(registerDto.email).pipe(
      switchMap((emailExists: boolean) => {
        if (!emailExists) {
          return this.usernameExists(registerDto.username).pipe(
            switchMap((usernameExists: boolean) => {
              if (!usernameExists) {
                return this.hashPassword(registerDto.password).pipe(
                  switchMap((passwordHash: string) => {
                    registerDto.password = passwordHash;
                    return from(this.userRepository.save(registerDto)).pipe(
                      map((savedUser: IUser) => {
                        const { password, ...user } = savedUser;
                        return user;
                      }),
                      catchError((err) => throwError(err)),
                    );
                  }),
                );
              } else {
                throw new HttpException(
                  'Username aldready exists',
                  HttpStatus.CONFLICT,
                );
              }
            }),
          );
        } else {
          throw new HttpException('Email aldready exists', HttpStatus.CONFLICT);
        }
      }),
    );
  }

  login(loginDto: LoginDto): Observable<IJwt> {
    return this.findUserByEmail(loginDto.email).pipe(
      switchMap((user: IUser) => {
        if (user) {
          return this.validatePassword(loginDto.password, user.password).pipe(
            switchMap((passwordsMatches: boolean) => {
              if (passwordsMatches) {
                return this.generateJwt(user).pipe(map((jwt) => ({ jwt })));
              } else {
                throw new HttpException(
                  'Invalid credentials',
                  HttpStatus.UNAUTHORIZED,
                );
              }
            }),
          );
        } else {
          throw new HttpException(
            'Invalid credentials',
            HttpStatus.UNAUTHORIZED,
          );
        }
      }),
    );
  }

  private findUserByEmail(email: string): Observable<IUser> {
    return from(
      this.userRepository.findOne(
        { email },
        { select: ['id', 'email', 'username', 'password'] },
      ),
    );
  }

  private validatePassword(
    password: string,
    storedPasswordHash: string,
  ): Observable<boolean> {
    return this.comparePasswords(password, storedPasswordHash);
  }

  private emailExists(email: string): Observable<boolean> {
    return from(this.userRepository.findOne({ email })).pipe(
      map((user: IUser) => (user ? true : false)),
    );
  }

  private usernameExists(username: string): Observable<boolean> {
    return from(this.userRepository.findOne({ username })).pipe(
      map((user: IUser) => (user ? true : false)),
    );
  }

  generateJwt(user: IUser): Observable<string> {
    return from(this.jwtService.signAsync({ user }));
  }

  hashPassword(password: string): Observable<string> {
    return from(bcrypt.hash(password, 12));
  }

  comparePasswords(
    password: string,
    storedPasswordHash: string,
  ): Observable<any> {
    return from(bcrypt.compare(password, storedPasswordHash));
  }
}
