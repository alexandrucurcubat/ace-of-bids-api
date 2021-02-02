import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { from, Observable, throwError } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';

import { UserEntity } from '../models/user.entity';
import { IUser } from '../models/user.interface';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
  ) {}

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
}
