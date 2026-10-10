import { Component, type ErrorInfo, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle } from 'lucide-react';
import { Button } from '@/components/common/Button';

/**
 * Keeps a crash inside the revision editor from taking the whole application
 * down with it. The client has no error boundary of its own, so an exception
 * thrown while rendering the editor used to unmount everything — a blank page,
 * and every unsaved edit gone.
 *
 * What was typed is not held here: the editor keeps each edit in this tab's
 * `sessionStorage` as it happens (`RevisionEditor`), and offers it back when it
 * is opened again. "Reopen" does exactly that.
 */
interface Props {
  children: ReactNode;
  onClose: () => void;
}

interface State {
  error: Error | null;
}

export class EditorErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // eslint-disable-next-line no-console
    console.error('template editor crashed', error, info.componentStack);
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <EditorCrashed
        message={this.state.error.message}
        onReopen={() => this.setState({ error: null })}
        onClose={this.props.onClose}
      />
    );
  }
}

function EditorCrashed({ message, onReopen, onClose }: { message: string; onReopen: () => void; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3 rounded-lg border border-status-down/50 bg-status-down/5 p-4">
      <p className="flex items-center gap-2 text-sm font-semibold text-status-down">
        <AlertTriangle size={16} />
        {t('templates.editor.crashed', { defaultValue: 'The editor stopped on an unexpected error.' })}
      </p>
      <p className="text-xs text-text-secondary">
        {t('templates.editor.crashedKept', {
          defaultValue:
            'Your changes up to the last one before the error were kept in this browser tab: reopen the editor to get them back.',
        })}
      </p>
      <p className="break-words font-mono text-[11px] text-text-muted">{message}</p>
      <div className="flex gap-2">
        <Button size="sm" onClick={onReopen}>
          {t('templates.editor.reopen', { defaultValue: 'Reopen the editor' })}
        </Button>
        <Button size="sm" variant="secondary" onClick={onClose}>
          {t('templates.editor.backToList', { defaultValue: 'Back to the list' })}
        </Button>
      </div>
    </div>
  );
}
