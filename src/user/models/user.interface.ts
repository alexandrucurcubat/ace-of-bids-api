export interface IUser {
  id?: number;
  email?: string;
  username?: string;
  password?: string;
  role?: UserRole;
}

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
}
