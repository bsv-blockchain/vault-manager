import React from 'react'
import ReactDOM from 'react-dom/client'
import { CssBaseline } from '@mui/material'
import { ThemeProvider } from '@mui/material/styles'
import App from './App'
import web3Theme from './theme'
import { ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'

const rootElement = document.getElementById('root')

if (rootElement === null) {
  throw new Error('Failed to find the root element')
}

const root = ReactDOM.createRoot(rootElement)

root.render(
  <ThemeProvider theme={web3Theme}>
    <ToastContainer
      position="top-center"
      autoClose={5000} // auto close after 5 seconds
      hideProgressBar={false}
      newestOnTop={false}
      closeOnClick
      rtl={false} // set to true if you're using a right-to-left language
      pauseOnFocusLoss
      draggable
      pauseOnHover
    />
    <CssBaseline />
    <style>{`
      input:-webkit-autofill,
      textarea:-webkit-autofill,
      select:-webkit-autofill {
        -webkit-text-fill-color: #111 !important;
        transition: background-color 9999s ease-out, color 9999s ease-out;
      }
      ::placeholder { color: #888; }
    `}</style>
    <App />
  </ThemeProvider>
)
