<template>
  <nav class="flex items-center justify-center gap-2 select-none" aria-label="Pagination">
    <button
      class="px-2 py-1 rounded hover:bg-accent disabled:opacity-50"
      :disabled="page === 1"
      @click="$emit('update:page', 1)"
      aria-label="First Page"
    >«</button>
    <template v-for="item in pageItems" :key="item.key">
      <button
        v-if="item.type === 'page'"
        class="px-3 py-1 rounded font-medium hover:bg-accent"
        :class="item.value === page ? 'bg-primary text-primary-foreground' : 'text-foreground'"
        @click="$emit('update:page', item.value)"
        :aria-current="item.value === page ? 'page' : undefined"
      >
        {{ item.value }}
      </button>
      <span v-else class="px-2 text-muted-foreground">…</span>
    </template>
    <button
      class="px-2 py-1 rounded hover:bg-accent disabled:opacity-50"
      :disabled="page === totalPages"
      @click="$emit('update:page', totalPages)"
      aria-label="Last Page"
    >»</button>
  </nav>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({
  page: { type: Number, required: true },
  total: { type: Number, required: true },
  itemsPerPage: { type: Number, required: true },
  maxVisible: { type: Number, default: 7 }, // 最多显示多少个页码（含省略号）
})
const emit = defineEmits(['update:page'])
const totalPages = computed(() => Math.max(1, Math.ceil(props.total / props.itemsPerPage)))

function getPageItems(page, totalPages, maxVisible = 7) {
  // 只显示 1, totalPages, 当前页附近 2~3 个，省略号
  if (totalPages <= maxVisible) {
    return Array.from({ length: totalPages }, (_, i) => ({ type: 'page', value: i + 1, key: i + 1 }))
  }
  const items = []
  const showCount = maxVisible - 2 // 除去首尾
  let left = Math.max(2, page - Math.floor(showCount / 2))
  let right = Math.min(totalPages - 1, page + Math.floor(showCount / 2))
  if (page <= Math.ceil(showCount / 2)) {
    left = 2
    right = showCount + 1
  } else if (page >= totalPages - Math.floor(showCount / 2)) {
    left = totalPages - showCount
    right = totalPages - 1
  }
  // 首页
  items.push({ type: 'page', value: 1, key: 1 })
  // 左省略号
  if (left > 2) items.push({ type: 'ellipsis', key: 'left' })
  // 中间页
  for (let i = left; i <= right; i++) {
    items.push({ type: 'page', value: i, key: i })
  }
  // 右省略号
  if (right < totalPages - 1) items.push({ type: 'ellipsis', key: 'right' })
  // 末页
  items.push({ type: 'page', value: totalPages, key: totalPages })
  return items
}

const pageItems = computed(() => getPageItems(props.page, totalPages.value, props.maxVisible))
</script> 