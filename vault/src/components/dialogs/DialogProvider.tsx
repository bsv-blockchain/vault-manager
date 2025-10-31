import React, { FC, ReactNode, createContext, useCallback, useContext, useState } from 'react'
import DialogHost, { DialogRequest } from './DialogHost'

export type DialogAPI = {
  alert(msg: string, title?: string): Promise<void>
  confirm(
    msg: string,
    opts?: { title?: string; confirmText?: string; cancelText?: string }
  ): Promise<boolean>
  prompt(
    msg: string,
    opts?: {
      title?: string
      password?: boolean
      defaultValue?: string
      placeholder?: string
      maxLength?: number
      validate?: (val: string) => true | string
    }
  ): Promise<string | null>
}

const DialogCtx = createContext<DialogAPI | null>(null)

export const DialogProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [queue, setQueue] = useState<DialogRequest[]>([])

  const push = useCallback(
    <T,>(req: any) =>
      new Promise<T>((resolve) => setQueue((q) => [...q, { ...req, resolve }])),
    []
  )

  const api: DialogAPI = {
    alert: (message, title) => push<void>({ kind: 'alert', title, message }),
    confirm: (message, opts) =>
      push<boolean>({
        kind: 'confirm',
        title: opts?.title,
        message,
        confirmText: opts?.confirmText,
        cancelText: opts?.cancelText
      }),
    prompt: (message, opts) =>
      push<string | null>({
        kind: 'prompt',
        title: opts?.title,
        message,
        password: opts?.password,
        defaultValue: opts?.defaultValue,
        placeholder: opts?.placeholder,
        maxLength: opts?.maxLength,
        validate: opts?.validate
      })
  }

  return (
    <DialogCtx.Provider value={api}>
      {children}
      <DialogHost queue={queue} setQueue={setQueue} />
    </DialogCtx.Provider>
  )
}

export const useDialog = () => {
  const ctx = useContext(DialogCtx)
  if (!ctx) throw new Error('useDialog must be used within DialogProvider')
  return ctx
}
