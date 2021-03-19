import { UserRole } from './user-role.enum';

export interface IUser {
  id?: number;
  email?: string;
  username?: string;
  password?: string;
  role?: UserRole;
  jwt?: string;
}
