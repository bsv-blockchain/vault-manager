import React, { FC, ReactNode } from 'react'

interface ModalProps {
  title: string
  children: ReactNode
  onClose: () => void
}

const COLORS = {
  bg: '#1a1d24',
  bgPrimary: '#0f1216',
  border: '#3a3f49',
  borderAccent: 'rgba(201, 169, 97, 0.2)',
  accent: '#c9a961',
  text: '#e4e6eb',
  textSecondary: '#9da3ae'
}

const Modal: FC<ModalProps> = ({ title, children, onClose }) => {
  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(15, 18, 22, 0.95)',
        backdropFilter: 'blur(10px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: 16
      }}
    >
      <div
        style={{
          background: COLORS.bg,
          color: COLORS.text,
          padding: 24,
          borderRadius: 6,
          minWidth: 320,
          maxWidth: 600,
          width: '95%',
          border: `1px solid ${COLORS.border}`,
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(201, 169, 97, 0.05)'
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderBottom: `1px solid ${COLORS.borderAccent}`,
            paddingBottom: 12,
            marginBottom: 20,
            gap: 12
          }}
        >
          <h2
            style={{
              margin: 0,
              fontSize: 16,
              fontWeight: 600,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              color: COLORS.accent
            }}
          >
            {title}
          </h2>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: `1px solid ${COLORS.border}`,
              borderRadius: 4,
              padding: '4px 10px',
              fontSize: 20,
              cursor: 'pointer',
              lineHeight: 1,
              color: COLORS.textSecondary,
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = COLORS.accent
              e.currentTarget.style.borderColor = COLORS.accent
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = COLORS.textSecondary
              e.currentTarget.style.borderColor = COLORS.border
            }}
          >
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

export default Modal
