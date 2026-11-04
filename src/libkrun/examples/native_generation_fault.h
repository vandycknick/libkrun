/* SPDX-License-Identifier: GPL-2.0-only
 * Isolated standalone proof instrumentation, never a production kernel input.
 * Included after the unchanged production low-last silo_publish_exact helper.
 */
static unsigned int proof_mode;
module_param(proof_mode, uint, 0400);
MODULE_PARM_DESC(proof_mode, "DIAGNOSTIC ONLY: 1=rejected ACK gates, 2=late ACK, 3=absent driver");

static bool silo_proof_gate(struct silo_vmgenid *g, unsigned int phase)
{
	WRITE_ONCE(g->proof_phase, phase);
	wait_event_timeout(g->stop_wait,
		READ_ONCE(g->stopping) || READ_ONCE(g->proof_gate) >= phase,
		msecs_to_jiffies(4000));
	return !READ_ONCE(g->stopping) && READ_ONCE(g->proof_gate) >= phase;
}

static void silo_publish(struct silo_vmgenid *g, const struct silo_request *r)
{
	struct silo_request wrong;

	if (proof_mode == 2 && !(r->flags & SILO_CLOCK_ONLY)) {
		WRITE_ONCE(g->proof_phase, 4);
		wait_event_timeout(g->stop_wait, READ_ONCE(g->stopping),
			msecs_to_jiffies(6000));
		if (READ_ONCE(g->stopping))
			return;
	} else if (proof_mode == 1 && !(r->flags & SILO_CLOCK_ONLY) &&
		   g->proof_previous.sequence && g->proof_previous.sequence != r->sequence) {
		WRITE_ONCE(g->proof_gate, 0);
		wrong = *r;
		wrong.sequence ^= 1;
		silo_publish_exact(g, &wrong);
		if (!silo_proof_gate(g, 1))
			return;
		wrong = *r;
		wrong.id[0] ^= 1;
		silo_publish_exact(g, &wrong);
		if (!silo_proof_gate(g, 2))
			return;
		silo_publish_exact(g, &g->proof_previous);
		if (!silo_proof_gate(g, 3))
			return;
	}
	silo_publish_exact(g, r);
	g->proof_previous = *r;
	WRITE_ONCE(g->proof_phase, 0);
}

static ssize_t generation_proof_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct silo_vmgenid *g = dev_to_virtio(dev)->priv;

	return sysfs_emit(buf, "mode=%u phase=%u gate=%u\n", proof_mode,
		READ_ONCE(g->proof_phase), READ_ONCE(g->proof_gate));
}

static ssize_t generation_proof_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct silo_vmgenid *g = dev_to_virtio(dev)->priv;
	unsigned int phase = READ_ONCE(g->proof_phase);

	if (!sysfs_streq(buf, "advance") || proof_mode != 1 || phase < 1 || phase > 3)
		return -EINVAL;
	WRITE_ONCE(g->proof_gate, phase);
	wake_up(&g->stop_wait);
	return count;
}
static DEVICE_ATTR_RW(generation_proof);
