/** Rectangular 28px controls. Hover inverts; focus is a structure outline. */

import type { ButtonHTMLAttributes, ReactNode } from 'react';

import { Icon, type IconName } from './icons';

type Variant = 'default' | 'primary' | 'threat' | 'quiet';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  icon?: IconName;
  small?: boolean;
  children?: ReactNode;
}

const VARIANT_CLASS: Record<Variant, string> = {
  default: '',
  primary: 'btn-primary',
  threat: 'btn-threat',
  quiet: 'btn-quiet',
};

export function Button({
  variant = 'default',
  icon,
  small = false,
  children,
  className,
  type = 'button',
  ...rest
}: ButtonProps) {
  const classes = ['btn', VARIANT_CLASS[variant], small ? 'btn-small' : '', className ?? '']
    .filter(Boolean)
    .join(' ');
  return (
    <button type={type} className={classes} {...rest}>
      {icon ? <Icon name={icon} size={small ? 12 : 14} /> : null}
      {children}
    </button>
  );
}
