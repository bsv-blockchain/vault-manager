import React, { FC, useEffect } from 'react'
import { Notification } from '../../types'

interface NotificationBannerProps {
  notification: Notification
  onDismiss: () => void
}

const NotificationBanner: FC<NotificationBannerProps> = ({ notification, onDismiss }) => {
  const colors = { success: '#4CAF50', error: '#8b0000', info: '#2196F3' }

  useEffect(() => {
    const timer = setTimeout(onDismiss, 5000)
    return () => clearTimeout(timer)
  }, [notification.id, onDismiss])

  return (
    <div style={{
      position: 'fixed',
      top: 12,
      right: 12,
      background: colors[notification.type],
      color: 'white',
      padding: '12px 16px',
      borderRadius: 12,
      zIndex: 1000,
      boxShadow: '0 8px 24px rgba(0,0,0,0.2)',
      display: 'flex',
      alignItems: 'center',
      gap: 16,
      maxWidth: '90vw'
    }}>
      <span style={{ wordBreak: 'break-word' }}>{notification.message}</span>
      <button
        onClick={onDismiss}
        style={{
          background: 'none',
          border: 'none',
          color: 'white',
          fontSize: 22,
          cursor: 'pointer',
          lineHeight: 1,
          padding: 0
        }}
      >
        &times;
      </button>
    </div>
  )
}

export default NotificationBanner
