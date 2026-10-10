import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { configApi } from '@/api/config.api';

/**
 * « Collecter maintenant » from the device page's header: the same call and
 * the same three sentences as the Configuration tab's button — a new snapshot,
 * an identical one confirmed (a SUCCESS, not "nothing happened"), or the
 * server's own refusal, kept word for word because each refusal of that route
 * has a different owner (no SSH channel, no collector for the family, a
 * tunnel down…).
 */
export function useCollectNow(deviceId: number, onCollected: () => void): { collect: () => Promise<void>; collecting: boolean } {
  const { t } = useTranslation();
  const [collecting, setCollecting] = useState(false);

  const collect = useCallback(async () => {
    setCollecting(true);
    try {
      const r = await configApi.collect(deviceId);
      if (r.snapshot.created) {
        toast.success(t('config.collectStored', { hash: r.snapshot.ncmHash ? r.snapshot.ncmHash.slice(0, 12) : '—' }));
      } else {
        toast.success(t('config.collectUnchanged', { seen: r.snapshot.seenCount }));
      }
      if (r.warnings.length > 0) {
        toast(t('config.collectWarnings', { n: r.warnings.length, first: r.warnings[0] }), { duration: 9000 });
      }
      onCollected();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('config.collectFailed'), { duration: 9000 });
    } finally {
      setCollecting(false);
    }
  }, [deviceId, onCollected, t]);

  return { collect, collecting };
}
