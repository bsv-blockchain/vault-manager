import ReactDOM from 'react-dom/client'
import App from './App'

const rootElement = document.getElementById('root')

if (rootElement === null) {
  throw new Error('Failed to find the root element')
}

const root = ReactDOM.createRoot(rootElement)

root.render(
  <>
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
  </>
)
