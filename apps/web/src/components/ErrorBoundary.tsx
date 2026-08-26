import { Component, type ReactNode } from 'react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        this.props.fallback ?? (
          <div className="error-banner">
            <p style={{ margin: '0 0 8px', fontWeight: 600 }}>Something went wrong</p>
            <p style={{ margin: 0, fontSize: 13 }}>{this.state.error.message}</p>
            <button
              className="btn"
              style={{ marginTop: 12 }}
              onClick={() => this.setState({ error: null })}
            >
              Try again
            </button>
          </div>
        )
      )
    }
    return this.props.children
  }
}
