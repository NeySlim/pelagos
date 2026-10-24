// SPDX-License-Identifier: Apache-2.0
import { Key } from '@phosphor-icons/react'
import { AreaPlaceholder } from '../../components/AreaPlaceholder'
import { api } from '../../services/api'

export default function AclsKeysPage() {
  return <AreaPlaceholder ns="dns" page="aclsKeys" icon={Key} load={() => Promise.all([api.dns.acls(), api.dns.keys()]).then(([acls, keys]) => ({ acls, keys }))} endpoint="GET /dns/acls, GET /dns/keys" />
}
