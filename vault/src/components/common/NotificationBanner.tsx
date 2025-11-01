import React, { FC, useEffect } from 'react'
import { Notification } from '../../types'

interface NotificationBannerProps {
  notification: Notification
  onDismiss: () => void
}

const NotificationBanner: FC<NotificationBannerProps> = ({ notification, onDismiss }) => {
  const colors = {
    success: { bg: 'rgba(90, 147, 103, 0.2)', border: '#5a9367', text: '#5a9367' },
    error: { bg: 'rgba(196, 92, 92, 0.2)', border: '#c45c5c', text: '#c45c5c' },
    info: { bg: 'rgba(93, 140, 184, 0.2)', border: '#5d8cb8', text: '#5d8cb8' }
  }

  const style = colors[notification.type]

  useEffect(() => {
    const timer = setTimeout(onDismiss, 5000)
    return () => clearTimeout(timer)
  }, [notification.id, onDismiss])

  return (
    <div style={{
      position: 'fixed',
      top: 16,
      right: 16,
      background: style.bg,
      border: `1px solid ${style.border}`,
      backdropFilter: 'blur(10px)',
      color: style.text,
      padding: '14px 18px',
      borderRadius: 4,
      zIndex: 1000,
      boxShadow: `0 8px 24px rgba(0,0,0,0.4), 0 0 0 1px ${style.border}`,
      display: 'flex',
      alignItems: 'center',
      gap: 18,
      maxWidth: '90vw',
      fontSize: 13,
      fontWeight: 600,
      letterSpacing: '0.02em'
    }}>
      <span style={{ wordBreak: 'break-word', color: '#e4e6eb' }}>{notification.message}</span>
      <button
        onClick={onDismiss}
        style={{
          background: 'none',
          border: 'none',
          color: style.text,
          fontSize: 20,
          cursor: 'pointer',
          lineHeight: 1,
          padding: 0,
          fontWeight: 400,
          opacity: 0.8,
          transition: 'opacity 0.2s'
        }}
        onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
        onMouseLeave={(e) => e.currentTarget.style.opacity = '0.8'}
      >
        ×
      </button>
    </div>
  )
}

export default NotificationBanner
