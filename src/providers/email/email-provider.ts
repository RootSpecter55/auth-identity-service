export type Email = { to: string; subject: string; text: string };

export interface EmailProvider {
  send(email: Email): Promise<void>;
}
