import React, { FC, ReactNode } from 'react'

interface ModalProps {
  title: string
  children: ReactNode
  onClose: () => void
}

const COLORS = {
  border: '#ddd'
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
        background: 'rgba(0, 0, 0, 0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: 8
      }}
    >
      <div
        style={{
          background: 'white',
          color: '#111',
          padding: 12,
          borderRadius: 12,
          minWidth: 280,
          maxWidth: 900,
          width: '95%'
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderBottom: `1px solid ${COLORS.border}`,
            paddingBottom: 8,
            marginBottom: 12,
            gap: 8
          }}
        >
          <h2 style={{ margin: 0, fontSize: 18 }}>{title}</h2>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              fontSize: 28,
              cursor: 'pointer',
              lineHeight: 1
            }}
          >
            &times;
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

export default Modal
