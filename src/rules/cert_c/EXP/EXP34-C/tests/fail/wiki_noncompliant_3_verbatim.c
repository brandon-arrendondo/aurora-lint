/*
 * Rule: EXP34-C
 * Source: wiki, CERT EXP34-C "Noncompliant Code Example" (the third, tun driver), verbatim
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * tun comes from __tun_get(), which has no body in the scanned source to
 * prove it non-null, and tun->sk is read before the `if (!tun)` test that
 * follows it.
 */

static unsigned int tun_chr_poll(struct file *file, poll_table *wait)  {
  struct tun_file *tfile = file->private_data;
  struct tun_struct *tun = __tun_get(tfile);
  struct sock *sk = tun->sk;
  unsigned int mask = 0;

  if (!tun)
    return POLLERR;

  DBG(KERN_INFO "%s: tun_chr_poll\n", tun->dev->name);

  poll_wait(file, &tun->socket.wait, wait);

  if (!skb_queue_empty(&tun->readq))
    mask |= POLLIN | POLLRDNORM;

  if (sock_writeable(sk) ||
     (!test_and_set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags) &&
     sock_writeable(sk)))
    mask |= POLLOUT | POLLWRNORM;

  if (tun->dev->reg_state != NETREG_REGISTERED)
    mask = POLLERR;

  tun_put(tun);
  return mask;
}
