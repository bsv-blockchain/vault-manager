import { type BEEF, type LockingScript } from '@bsv/sdk'

declare module 'react-toastify'
declare module '@mui/material'
declare module '@mui/material/styles'
declare module '@mui/icons-material/GetApp'

// Interfaces used, it is necessary to declare them here
export interface Task {
  task: string
  sats: number
  outpoint: string
  lockingScript: string
  beef: BEEF | undefined
}
