import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { from, Observable, throwError } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';

import { AuthService } from 'src/auth/services/auth.service';
import { CreateUserDto } from '../models/dto/create-user.dto';
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

  create(createUserDto: CreateUserDto): Observable<IUser> {
    return this.emailExists(createUserDto.email).pipe(
      switchMap((exists: boolean) => {
        if (!exists) {
          return this.authService.hashPassword(createUserDto.password).pipe(
            switchMap((passwordHash: string) => {
              createUserDto.password = passwordHash;
              return from(this.userRepository.save(createUserDto)).pipe(
                catchError((err) => throwError(err)),
              );
            }),
          );
        } else {
          throw new HttpException('Email aldready exists', HttpStatus.CONFLICT);
        }
      }),
    );
  }

  login(loginUserDto: LoginUserDto): Observable<string> {
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
                  'Invalid password',
                  HttpStatus.UNAUTHORIZED,
                );
              }
            }),
          );
        } else {
          throw new HttpException('Email not found', HttpStatus.NOT_FOUND);
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

  // paginate(options: IPaginationOptions): Observable<Pagination<IUser>> {
  //   return from(paginate<IUser>(this.userRepository, options)).pipe(
  //     catchError((err) => throwError(err)),
  //   );
  // }

  // paginateFilterByUsername(
  //   options: IPaginationOptions,
  //   user: IUser,
  // ): Observable<Pagination<IUser>> {
  //   return from(
  //     this.userRepository.findAndCount({
  //       skip: options.page * options.limit || 0,
  //       take: options.limit || 10,
  //       order: { id: 'ASC' },
  //       select: ['id', 'username', 'email', 'role'],
  //       where: [{ username: Like(`%${user.username}%`) }],
  //     }),
  //   ).pipe(
  //     map(([users, totalUsers]) => {
  //       const usersPageable: Pagination<IUser> = {
  //         items: users,
  //         links: {
  //           first: options.route + `?limit=${options.limit}`,
  //           previous: options.route + ``,
  //           next:
  //             options.route +
  //             `?limit=${options.limit}&page=${options.page + 1}`,
  //           last:
  //             options.route +
  //             `?limit=${options.limit}&page=${Math.ceil(
  //               totalUsers / options.limit,
  //             )}`,
  //         },
  //         meta: {
  //           currentPage: options.page,
  //           itemCount: users.length,
  //           itemsPerPage: options.limit,
  //           totalItems: totalUsers,
  //           totalPages: Math.ceil(totalUsers / options.limit),
  //         },
  //       };
  //       return usersPageable;
  //     }),
  //   );
  // }

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
}
