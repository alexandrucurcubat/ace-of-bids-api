import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { from, Observable, throwError } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';

import { AuthService } from 'src/auth/services/auth.service';
import { RegisterUserDto } from '../models/dto/register-user.dto';
import { UserEntity } from '../models/user.entity';
import { IUser } from '../models/user.interface';
import { LoginUserDto } from '../models/dto/login-user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    private authService: AuthService,
  ) {}

  register(registerUserDto: RegisterUserDto): Observable<IUser> {
    return this.emailExists(registerUserDto.email).pipe(
      switchMap((emailExists: boolean) => {
        if (!emailExists) {
          return this.usernameExists(registerUserDto.username).pipe(
            switchMap((usernameExists: boolean) => {
              if (!usernameExists) {
                return this.authService
                  .hashPassword(registerUserDto.password)
                  .pipe(
                    switchMap((passwordHash: string) => {
                      registerUserDto.password = passwordHash;
                      return from(
                        this.userRepository.save(registerUserDto),
                      ).pipe(
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

  login(loginUserDto: LoginUserDto): Observable<string> {
    console.log(loginUserDto);
    return this.findUserByEmail(loginUserDto.email).pipe(
      switchMap((user: IUser) => {
        if (user) {
          return this.validatePassword(
            loginUserDto.password,
            user.password,
          ).pipe(
            switchMap((passwordsMatches: boolean) => {
              if (passwordsMatches) {
                return this.findOne(user.id).pipe(
                  switchMap((user: IUser) =>
                    this.authService.generateJwt(user),
                  ),
                  catchError((err) => throwError(err)),
                );
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

  findAll(): Observable<IUser[]> {
    return from(this.userRepository.find()).pipe(
      catchError((err) => throwError(err)),
    );
  }

  findOne(id: number): Observable<IUser> {
    return from(this.userRepository.findOne({ id })).pipe(
      catchError((err) => throwError(err)),
    );
  }

  updateOne(id: number, user: IUser): Observable<IUser> {
    delete user.email;
    delete user.password;
    delete user.role;

    return from(this.userRepository.update(id, user)).pipe(
      switchMap(() => this.findOne(id)),
      catchError((err) => throwError(err)),
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
    return this.authService.comparePasswords(password, storedPasswordHash);
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
}
