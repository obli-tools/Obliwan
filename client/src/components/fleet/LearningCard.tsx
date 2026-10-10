import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Camera, GraduationCap, LogOut } from 'lucide-react';
import type { LearningCaptureDetail } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { apiErrorText } from '@/components/variables/valueKinds';
import { learningApi } from '@/api/learning.api';

/**
 * Learning mode on one router's page (platform admins only — the caller
 * decides; the server refuses anybody else). The flag, a capture, the last
 * capture's summary, and the way to the learning page.
 */
export function LearningCard({
  deviceId,
  learning,
  onChanged,
}: {
  deviceId: number;
  learning: { since: string; byUserId: number | null } | null;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const [detail, setDetail] = useState<LearningCaptureDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadDetail = useCallback(() => {
    learningApi.capture(deviceId).then(setDetail).catch(() => setDetail(null));
  }, [deviceId]);
  useEffect(() => loadDetail(), [loadDetail]);

  const toggle = async (): Promise<void> => {
    if (learning && !window.confirm(t('learning.confirm.disable'))) return;
    setBusy(true);
    setError(null);
    try {
      await learningApi.setLearning(deviceId, !learning);
      onChanged();
    } catch (err) {
      setError(apiErrorText(err) ?? String(err));
    } finally {
      setBusy(false);
    }
  };

  const capture = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await learningApi.startCapture([deviceId]);
      toast.success(t('learning.run.started', { count: 1 }));
      setTimeout(loadDetail, 4000);
    } catch (err) {
      setError(apiErrorText(err) ?? String(err));
    } finally {
      setBusy(false);
    }
  };

  const facts = detail?.facts ?? null;
  return (
    <div className="space-y-2 text-sm">
      <p className="text-text-primary">
        {learning
          ? t('learning.since', { date: new Date(learning.since).toLocaleString() })
          : t('learning.off')}
      </p>
      {learning && <p className="text-xs text-text-muted">{t('learning.refusalHint')}</p>}
      {detail && (
        <p className="text-xs text-text-muted">
          {t(`learning.status.${detail.status}`)}
          {detail.reason ? ` — ${t(`learning.reason.${detail.reason}`)}` : ''}
          {` · ${new Date(detail.finishedAt ?? detail.startedAt).toLocaleString()}`}
          {facts ? ` · WAN1 ${t(`learning.facts.wan1Mode.${facts.wan1.mode}`)}${facts.wan1.pppoeName ? ` (${facts.wan1.pppoeName})` : ''}` : ''}
          {detail.status === 'succeeded' ? ` · ${t('learning.table.vaulted')}: ${detail.secrets.length}` : ''}
        </p>
      )}
      {error && <p className="text-xs text-red-400">{error}</p>}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant={learning ? 'danger' : 'primary'} loading={busy} onClick={() => void toggle()}>
          {learning ? <LogOut size={14} /> : <GraduationCap size={14} />}
          {learning ? t('learning.actions.disable') : t('learning.actions.enable')}
        </Button>
        <Button size="sm" variant="secondary" disabled={!learning || busy} onClick={() => void capture()}>
          <Camera size={14} /> {t('learning.actions.capture')}
        </Button>
        <Link to={`/manage/learning?device=${deviceId}`} className="self-center text-xs text-accent hover:underline">
          {t('learning.actions.openPage')}
        </Link>
      </div>
    </div>
  );
}
